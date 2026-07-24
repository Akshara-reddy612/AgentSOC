"""
perception/derived_context_rules.py

Pure functions that compute DerivedContext flags from ImmutableContext only.

SECURITY INVARIANT: No function here accepts Evidence as input.
  - Type annotations declare ImmutableContext as the only accepted argument.
  - Runtime isinstance() checks enforce this — passing an Evidence (or any
    other) object raises TypeError immediately, making the contamination path
    structurally impossible.

All functions are deterministic: same ImmutableContext -> same output, always.
No hidden state, no randomness, no I/O.
"""

from __future__ import annotations

from perception.models import (
    DerivedContext,
    Evidence,        # imported ONLY to use in the isinstance guard
    ImmutableContext,
    TrustedField,
    TrustLevel,
)
from perception.source_systems import SourceSystem

# Source system used to tag all derived facts
_SYSTEM = SourceSystem.SYSTEM

# Host criticality values that constitute "high" risk
_HIGH_CRITICALITY_VALUES = frozenset({"high", "critical"})

# Privilege tiers that are considered elevated
_PRIVILEGED_TIERS = frozenset({"admin", "privileged"})


# ---------------------------------------------------------------------------
# Guard helper
# ---------------------------------------------------------------------------

def _require_immutable_context(obj: object, fn_name: str) -> ImmutableContext:
    """
    Runtime guard — raises TypeError if `obj` is not an ImmutableContext.

    This is the key enforcement point: passing Evidence here raises immediately
    rather than silently contaminating derived context.
    """
    if isinstance(obj, Evidence):
        raise TypeError(
            f"{fn_name}() received an Evidence object. "
            "Derived-context computation MUST use only ImmutableContext. "
            "Passing Evidence into derived-context functions is a security violation."
        )
    if not isinstance(obj, ImmutableContext):
        raise TypeError(
            f"{fn_name}() requires an ImmutableContext argument, "
            f"got {type(obj).__name__!r}."
        )
    return obj


def _derived_bool(value: bool) -> TrustedField:
    """Wrap a boolean derived result in a TrustedField."""
    return TrustedField(
        value=value,
        trust_level=TrustLevel.DERIVED,
        source_system=_SYSTEM,
    )


# ---------------------------------------------------------------------------
# Individual compute functions
# ---------------------------------------------------------------------------

def compute_no_prior_access(context: ImmutableContext) -> bool:
    """
    Return True if the (source_user, target_host) pair has no established
    access baseline in the knowledge store.

    Reads ImmutableContext.historical_access.value (a bool stored at
    normalization/contextualization time from the knowledge store).

    Args:
        context: ImmutableContext — the only accepted argument type.

    Returns:
        bool — True means "no prior access recorded" (anomalous).

    Raises:
        TypeError — if anything other than ImmutableContext is passed.
    """
    ctx = _require_immutable_context(context, "compute_no_prior_access")
    has_access = bool(ctx.historical_access.value)
    return not has_access


def compute_cross_zone_access(context: ImmutableContext) -> bool:
    """
    Return True if the source and target assets are in different network zones.

    Reads ImmutableContext.network_zone.value, which encodes zone information
    as a dict with 'src_zone' and 'dst_zone' keys (set by the contextualizer).

    Args:
        context: ImmutableContext — the only accepted argument type.

    Returns:
        bool — True means source and target are in different zones.

    Raises:
        TypeError — if anything other than ImmutableContext is passed.
    """
    ctx = _require_immutable_context(context, "compute_cross_zone_access")
    zone_data = ctx.network_zone.value
    if isinstance(zone_data, dict):
        src_zone = zone_data.get("src_zone", "UNKNOWN")
        dst_zone = zone_data.get("dst_zone", "UNKNOWN")
        return src_zone.upper() != dst_zone.upper()
    # If zone_data is a plain string (single zone), treat as same-zone
    return False


def compute_high_criticality_target(context: ImmutableContext) -> bool:
    """
    Return True if the target asset criticality is classified high or critical.

    Args:
        context: ImmutableContext — the only accepted argument type.

    Returns:
        bool — True means the target is a high-value asset.

    Raises:
        TypeError — if anything other than ImmutableContext is passed.
    """
    ctx = _require_immutable_context(context, "compute_high_criticality_target")
    crit_val = ctx.asset_criticality.value
    if isinstance(crit_val, dict):
        crit_str = crit_val.get("criticality", "unknown")
    else:
        crit_str = str(crit_val)
    return crit_str.lower() in _HIGH_CRITICALITY_VALUES


def compute_privilege_escalation_risk(context: ImmutableContext) -> bool:
    """
    Return True if there is a privilege-escalation risk signal.

    Heuristic: the source user's privilege tier is 'standard' (non-elevated)
    and the target host is classified as high/critical — implying the user
    may be attempting to access resources beyond their authorised tier.

    Args:
        context: ImmutableContext — the only accepted argument type.

    Returns:
        bool — True means escalation risk detected.

    Raises:
        TypeError — if anything other than ImmutableContext is passed.
    """
    ctx = _require_immutable_context(context, "compute_privilege_escalation_risk")
    user_role = str(ctx.user_role.value).lower()
    is_standard_user = user_role not in _PRIVILEGED_TIERS
    is_high_target = compute_high_criticality_target(ctx)
    return is_standard_user and is_high_target


# ---------------------------------------------------------------------------
# Builder — assembles all flags into a DerivedContext
# ---------------------------------------------------------------------------

def build_derived_context(context: ImmutableContext) -> DerivedContext:
    """
    Compute all derived flags and return a fully-populated DerivedContext.

    This is the canonical way for the contextualizer to call the rule engine.
    Each flag is computed by its own pure function and wrapped in a TrustedField.

    Args:
        context: ImmutableContext — knowledge-store-sourced facts.

    Returns:
        DerivedContext with all four flags populated.

    Raises:
        TypeError — if `context` is not an ImmutableContext.
    """
    # The guard in each compute_* call is redundant here (context is already
    # validated), but retained for defence-in-depth.
    return DerivedContext(
        no_prior_access=_derived_bool(compute_no_prior_access(context)),
        cross_zone_access=_derived_bool(compute_cross_zone_access(context)),
        high_criticality_target=_derived_bool(compute_high_criticality_target(context)),
        privilege_escalation_risk=_derived_bool(compute_privilege_escalation_risk(context)),
    )
