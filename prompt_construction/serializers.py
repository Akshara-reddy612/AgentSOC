"""
prompt_construction/serializers.py

Serializers for PromptPackage → string.

Design
------
Each serializer is a pure function: given a PromptPackage, it produces a
string.  No serializer ever modifies the PromptPackage or touches the
original Evidence objects.

Extensibility
-------------
Adding a new serializer (JSON, Markdown, etc.) requires:
1. Implementing a function with signature ``(pkg: PromptPackage) -> str``.
2. (Optional) Registering it in __all__ and documenting it here.
No changes to PromptPackage or safe_prompt_builder.py are needed.

XML serializer
--------------
The XML serializer produces:
    <prompt>
      <metadata>...</metadata>
      <instructions>...</instructions>
      <trusted_context>...</trusted_context>
      <untrusted_evidence>...</untrusted_evidence>
    </prompt>

CRITICAL: All evidence content is XML-escaped before insertion.
Reserved XML characters (&, <, >, ", ') are entity-encoded so that:
- A value containing ``</untrusted_evidence>`` cannot break out of its block.
- A value containing ``<script>`` cannot inject markup.
- A value containing ``&`` does not produce malformed XML.

The trusted_context block is also escaped defensively, even though its values
are system-controlled, because belt-and-suspenders escaping costs nothing.
"""

from __future__ import annotations

import json
from types import MappingProxyType
from typing import Any

from prompt_construction.package import PromptPackage
from prompt_construction.nce_package import NCEPromptPackage

__all__ = [
    "serialize_xml",
    "serialize_json",
    "serialize_nce_xml",
    "xml_escape",
    "xml_escape_value",
]

def _json_default_safe(o: Any) -> Any:
    if isinstance(o, MappingProxyType):
        return dict(o)
    return str(o)

# XML escape table — all reserved XML characters, plus single quote for
# completeness (required in attribute contexts; harmless in element content).
_XML_ESCAPE_TABLE: dict[str, str] = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&apos;",
}


def xml_escape(text: str) -> str:
    """
    Escape all reserved XML characters in `text`.

    This is the shared, canonical XML-escaping primitive used by every
    prompt-construction path in this codebase (currently: the verdict flow
    via safe_prompt_builder.py / serialize_xml(), and the NCE flow via
    nce_prompt_builder.py / serialize_nce_xml()).  One implementation,
    tested once, trusted everywhere — do NOT duplicate this logic.

    Applied to every string value before insertion into the XML output.
    Handles the full set of characters that could corrupt or break out of
    an XML element or attribute:
        &  →  &amp;   (must be first — otherwise escapes get double-escaped)
        <  →  &lt;
        >  →  &gt;
        "  →  &quot;
        '  →  &apos;

    Parameters
    ----------
    text : str
        Any string — including adversarial evidence field values.

    Returns
    -------
    str
        The input with all reserved XML characters replaced by their
        entity references.  Safe for insertion into XML element content.
    """
    if not text:
        return text
    # Process & first — otherwise subsequent replacements would corrupt the
    # newly inserted entity references (e.g. &lt; → &amp;lt;).
    result = text.replace("&", "&amp;")
    result = result.replace("<", "&lt;")
    result = result.replace(">", "&gt;")
    result = result.replace('"', "&quot;")
    result = result.replace("'", "&apos;")
    return result


def xml_escape_value(value: Any) -> str:
    """
    Convert an arbitrary value to a string and XML-escape it.

    This is the shared, canonical value-escaping primitive used by every
    prompt-construction path in this codebase (currently: the verdict flow
    via safe_prompt_builder.py / serialize_xml(), and the NCE flow via
    nce_prompt_builder.py / serialize_nce_xml()).  One implementation,
    tested once, trusted everywhere — do NOT duplicate this logic.

    Scalars are converted via str(); dicts and lists are JSON-serialized
    first so they remain human-readable in the output.
    """
    if isinstance(value, (dict, list, MappingProxyType)):
        raw = json.dumps(value, ensure_ascii=False, default=_json_default_safe)
    else:
        raw = str(value) if value is not None else ""
    return xml_escape(raw)


def _indent(text: str, spaces: int) -> str:
    """Indent every line of `text` by `spaces` spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line if line else line for line in text.split("\n"))


def _render_dict_as_xml_children(
    data: dict[str, Any],
    indent: int = 4,
) -> str:
    """
    Render a dict as XML child elements, escaping all values.

    Each key becomes an element tag.  Keys that are not valid XML tag names
    (e.g. contain dots or colons) are sanitized by replacing problematic
    characters with underscores.

    Example output (indent=4):
        <command_line>powershell -enc ...</command_line>
        <process_name>cmd.exe</process_name>
    """
    lines: list[str] = []
    for key, value in data.items():
        # Sanitize key to a valid XML element name:
        # replace dots, colons, spaces with underscores.
        safe_key = key.replace(".", "_").replace(":", "_").replace(" ", "_")
        # Strip leading digits (XML names cannot start with a digit)
        if safe_key and safe_key[0].isdigit():
            safe_key = "_" + safe_key

        escaped_value = xml_escape_value(value)
        prefix = " " * indent
        lines.append(f"{prefix}<{safe_key}>{escaped_value}</{safe_key}>")

    return "\n".join(lines)


def _render_evidence_entry(field_name: str, entry: dict[str, Any], indent: int) -> str:
    """
    Render one evidence field entry as nested XML.

    Structure:
        <field_name>
            <value>... (escaped)</value>
            <risk_metadata>... (JSON-escaped)</risk_metadata>
        </field_name>
    """
    prefix = " " * indent
    inner = " " * (indent + 4)

    raw_value = entry.get("value", "")
    risk_meta = entry.get("risk_metadata", {})

    escaped_value = xml_escape(str(raw_value))
    escaped_risk = xml_escape(json.dumps(risk_meta, ensure_ascii=False, default=_json_default_safe))

    lines = [
        f"{prefix}<{field_name}>",
        f"{inner}<value>{escaped_value}</value>",
        f"{inner}<risk_metadata>{escaped_risk}</risk_metadata>",
        f"{prefix}</{field_name}>",
    ]
    return "\n".join(lines)


def serialize_xml(pkg: PromptPackage) -> str:
    """
    Serialize a PromptPackage to an XML string.

    Structure
    ---------
    <?xml version="1.0" encoding="UTF-8"?>
    <prompt>
      <metadata>
        <builder_version>phase2</builder_version>
        ...
      </metadata>
      <instructions>...</instructions>
      <trusted_context>
        <immutable_context_user_role>analyst</immutable_context_user_role>
        ...
      </trusted_context>
      <untrusted_evidence>
        <command_line>
          <value>... (XML-escaped evidence value)</value>
          <risk_metadata>... (JSON-escaped risk metadata)</risk_metadata>
        </command_line>
        ...
      </untrusted_evidence>
    </prompt>

    Security guarantees
    -------------------
    - All evidence values are XML-escaped: ``<``, ``>``, ``&``, ``"``, ``'``
      are replaced by entity references before insertion.
    - A value containing ``</untrusted_evidence>`` becomes
      ``&lt;/untrusted_evidence&gt;`` — it CANNOT break out of its block.
    - A value containing ``<inject>`` becomes ``&lt;inject&gt;`` — no markup
      injection.
    - The trusted_context block is also escaped (belt-and-suspenders).

    Parameters
    ----------
    pkg : PromptPackage
        The structured intermediate representation produced by
        ``build_prompt_package()``.

    Returns
    -------
    str
        A valid, well-formed XML string safe for inclusion in an LLM prompt.
    """
    lines: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>', "<prompt>"]

    # --- metadata block ---
    lines.append("  <metadata>")
    lines.append(_render_dict_as_xml_children(pkg.metadata, indent=4))
    lines.append("  </metadata>")

    # --- instructions block ---
    escaped_instructions = xml_escape(pkg.instructions)
    lines.append(f"  <instructions>{escaped_instructions}</instructions>")

    # --- trusted_context block ---
    lines.append("  <trusted_context>")
    lines.append(_render_dict_as_xml_children(pkg.trusted_context, indent=4))
    lines.append("  </trusted_context>")

    # --- untrusted_evidence block ---
    lines.append("  <untrusted_evidence>")
    for field_name, entry in pkg.untrusted_evidence.items():
        if isinstance(entry, dict) and "value" in entry:
            lines.append(_render_evidence_entry(field_name, entry, indent=4))
        else:
            # Fallback: render as a simple escaped element
            prefix = "    "
            escaped_val = xml_escape_value(entry)
            lines.append(f"{prefix}<{field_name}>{escaped_val}</{field_name}>")
    lines.append("  </untrusted_evidence>")

    lines.append("</prompt>")
    return "\n".join(lines)


def serialize_json(pkg: PromptPackage) -> str:
    """
    Serialize a PromptPackage to a JSON string.

    No additional escaping is needed — json.dumps() handles all special
    characters.  The JSON serializer is provided as a second format to
    demonstrate that PromptPackage is format-agnostic.

    Parameters
    ----------
    pkg : PromptPackage
        The structured intermediate representation.

    Returns
    -------
    str
        A UTF-8 JSON string representing the full PromptPackage.
    """
    data = {
        "metadata": pkg.metadata,
        "instructions": pkg.instructions,
        "trusted_context": pkg.trusted_context,
        "untrusted_evidence": pkg.untrusted_evidence,
    }
    return json.dumps(data, ensure_ascii=False, indent=2, default=_json_default_safe)


def serialize_nce_xml(pkg: NCEPromptPackage) -> str:
    """
    Serialize an NCEPromptPackage to an XML string.

    Structure
    ---------
    <?xml version="1.0" encoding="UTF-8"?>
    <nce_prompt>
      <metadata>
        <nce_builder_version>nce-phase2</nce_builder_version>
        ...
      </metadata>
      <instructions>... (XML-escaped)</instructions>
      <untrusted_evidence>
        <command_line><value>... (XML-escaped)</value></command_line>
        ...
      </untrusted_evidence>
    </nce_prompt>

    IMPORTANT — NO <trusted_context> block:
        NCE receives evidence-only input by design.  The absence of a
        trusted_context block is intentional and structurally enforced:
        NCEPromptPackage has no trusted_context field, and this serializer
        produces no such block.  This makes the NCE/verdict-flow boundary
        visible to anyone reading raw XML output — there is no way to
        accidentally leak Knowledge Store context into NCE's prompt.

    Security guarantees
    -------------------
    - All evidence values are XML-escaped via the shared xml_escape()
      function — the same canonical implementation used by serialize_xml().
    - A value containing ``</untrusted_evidence>`` becomes
      ``&lt;/untrusted_evidence&gt;`` — it CANNOT break out of its block.
    - No escaping logic is reimplemented here; all escaping delegates to
      xml_escape() / xml_escape_value().

    Parameters
    ----------
    pkg : NCEPromptPackage
        The structured intermediate representation produced by
        ``build_nce_prompt_package()``.

    Returns
    -------
    str
        A valid, well-formed XML string safe for inclusion in an LLM prompt.
    """
    lines: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>', "<nce_prompt>"]

    # --- metadata block ---
    # Uses the same _render_dict_as_xml_children helper as serialize_xml()
    # for consistency.
    lines.append("  <metadata>")
    lines.append(_render_dict_as_xml_children(pkg.metadata, indent=4))
    lines.append("  </metadata>")

    # --- instructions block ---
    escaped_instructions = xml_escape(pkg.instructions)
    lines.append(f"  <instructions>{escaped_instructions}</instructions>")

    # --- untrusted_evidence block ---
    # No <trusted_context> block — NCE receives no trusted context, by design.
    # This is NOT an omission; it is a deliberate structural choice.  See the
    # module docstring of nce_package.py and nce_prompt_builder.py for the
    # design rationale.
    lines.append("  <untrusted_evidence>")
    for field_name, raw_value in pkg.evidence.items():
        # Sanitize field name to valid XML element name (same pattern as
        # _render_dict_as_xml_children).
        safe_key = field_name.replace(".", "_").replace(":", "_").replace(" ", "_")
        if safe_key and safe_key[0].isdigit():
            safe_key = "_" + safe_key

        # Per-field rendering: <field_name><value>escaped</value></field_name>
        # Same pattern as the verdict flow's _render_evidence_entry() MINUS
        # the <risk_metadata> sub-element (NCE evidence has no risk_metadata —
        # ERA scoring happens elsewhere in the pipeline and NCE explicitly
        # never sees it).
        escaped_value = xml_escape(str(raw_value))
        lines.append(f"    <{safe_key}>")
        lines.append(f"      <value>{escaped_value}</value>")
        lines.append(f"    </{safe_key}>")
    lines.append("  </untrusted_evidence>")

    lines.append("</nce_prompt>")
    return "\n".join(lines)
