"""
perception/source_systems.py

Strongly-typed SourceSystem enum.

Every code path that would otherwise accept an arbitrary string for a source
must use this enum.  Unknown values raise ValueError — never silently coerced.
"""

from enum import Enum


class SourceSystem(Enum):
    """
    Enumeration of recognised alert/data source systems.

    Values are kept as their string names so they serialise legibly
    (e.g., in pipeline log output and JSON exports).
    """
    EDR = "EDR"
    SIEM = "SIEM"
    WINDOWS_EVENT_LOG = "WINDOWS_EVENT_LOG"
    LINUX_SYSLOG = "LINUX_SYSLOG"
    CLOUD = "CLOUD"
    KNOWLEDGE_STORE = "KNOWLEDGE_STORE"
    SYSTEM = "SYSTEM"

    @classmethod
    def from_string(cls, value: str) -> "SourceSystem":
        """
        Parse a source-system name into the enum.

        Raises ValueError for any unrecognised string so callers cannot
        accidentally pass arbitrary free text as a source name.
        """
        try:
            return cls[value.upper()]
        except KeyError:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(
                f"Unrecognised source system {value!r}. "
                f"Valid values are: {valid}"
            )
