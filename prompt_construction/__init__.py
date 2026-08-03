"""
prompt_construction/__init__.py

Safe Prompt Construction (SPC) package.

Builds ``PromptPackage`` objects from risk-assessed ``EnrichedIncident``
instances and serializes them to safe string representations for LLM
consumption.

Exported public API
-------------------
    PromptPackage              — structured intermediate representation
    build_prompt_package       — constructs a PromptPackage from an incident
    serialize_xml              — serializes a PromptPackage to an XML string
"""

from prompt_construction.package import PromptPackage
from prompt_construction.safe_prompt_builder import build_prompt_package
from prompt_construction.serializers import serialize_xml

__all__ = [
    "PromptPackage",
    "build_prompt_package",
    "serialize_xml",
]
