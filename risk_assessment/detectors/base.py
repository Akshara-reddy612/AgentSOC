"""
risk_assessment/detectors/base.py

Abstract base interfaces for Evidence Risk Assessment detectors.

Two interface families
----------------------
FieldDetector
    Operates on a SINGLE evidence field.  Receives the normalized text and any
    decoded candidates for that field.  Returns a DetectorResult.
    Implemented this session: RegexDetector, SemanticDetector.

IncidentDetector
    Operates on ALL evidence fields together (the whole incident).  Receives a
    dict mapping field names to their NormalizationResults.  Returns a
    DetectorResult.
    Interface defined here now; concrete SplitFieldDetector is built in Session 2.

Why two interfaces?
-------------------
The input shapes are fundamentally different and must not be conflated:
- A FieldDetector's input is bounded to one field; it cannot "see" adjacent
  fields.  This makes per-field scores clean and interpretable.
- An IncidentDetector's input is the whole incident.  This allows detection of
  attacks that split injection phrases across multiple fields (e.g. the command
  starts a directive in `process_name` and completes it in `command_line`).
Mixing these into one interface would force FieldDetectors to accept a dict
they don't need and IncidentDetectors to pretend they only see one field.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from risk_assessment.results import DetectorResult, NormalizationResult


class FieldDetector(ABC):
    """
    Abstract base for detectors that operate on a single evidence field.

    Subclasses MUST implement `detect()`.  They MUST NOT modify the
    `normalized_text` or `decoded_candidates` arguments — these are read-only
    inputs produced by the normalization pipeline.

    Usage::

        result = detector.detect(
            normalized_text="ignore previous instructions",
            decoded_candidates=[],
        )

    Attributes
    ----------
    name : str
        A canonical, human-readable identifier for this detector.  Must be
        unique across all registered detectors.  Used in DetectorResult.detector.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical name of this detector."""

    @abstractmethod
    def detect(
        self,
        normalized_text: str,
        decoded_candidates: list[str],
    ) -> DetectorResult:
        """
        Run this detector on a single normalized evidence field.

        Parameters
        ----------
        normalized_text : str
            The normalized version of the evidence field (output of
            `normalize_text().normalized_text`).  Read-only.

        decoded_candidates : list[str]
            Zero or more strings decoded from obfuscated content (e.g. base64)
            found in the original field.  Detectors should check these in
            addition to `normalized_text`.  Read-only.

        Returns
        -------
        DetectorResult
            score=0.0 and empty matches/explanation if no hit detected.
        """


class IncidentDetector(ABC):
    """
    Abstract base for detectors that operate on ALL evidence fields together.

    Unlike FieldDetector, an IncidentDetector receives the entire incident's
    NormalizationResults so it can detect patterns that span multiple fields
    (e.g. split-field prompt injection).

    Concrete implementation (SplitFieldDetector) is built in Session 2.

    Attributes
    ----------
    name : str
        A canonical, human-readable identifier for this detector.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical name of this detector."""

    @abstractmethod
    def detect(
        self,
        all_fields: dict[str, NormalizationResult],
    ) -> DetectorResult:
        """
        Run this detector across all normalized evidence fields.

        Parameters
        ----------
        all_fields : dict[str, NormalizationResult]
            Keys are evidence field names (e.g. "command_line", "process_name").
            Values are their NormalizationResults.  All values are read-only.

        Returns
        -------
        DetectorResult
            score=0.0 and empty matches/explanation if no cross-field hit
            detected.
        """
