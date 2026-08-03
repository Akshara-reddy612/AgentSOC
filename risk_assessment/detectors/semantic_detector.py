"""
risk_assessment/detectors/semantic_detector.py

Embedding-based FieldDetector using sentence-transformers (all-MiniLM-L6-v2).

Why real sentence embeddings instead of TF-IDF?
-----------------------------------------------
TF-IDF similarity is vocabulary-overlap: two sentences sharing few or no
words score near zero even if they mean the same thing.  Prompt-injection
attacks deliberately paraphrase known triggers to defeat literal matching —
e.g. "stop adhering to prior directives" is semantically equivalent to
"ignore previous instructions" but shares only stop-word vocabulary.
Sentence embeddings encode *meaning*, not word identity, so they catch
paraphrases that both regex and TF-IDF miss.

Model choice: all-MiniLM-L6-v2
-------------------------------
- Small (~80 MB), runs on CPU, no API key, fully offline after first download.
- 384-dim embeddings; inference ~5–20ms per sentence on CPU.
- Cosine similarity in its embedding space is well-calibrated for
  semantic textual similarity tasks.
- Chosen over larger models because speed matters for a per-alert pipeline
  and the precision gain from larger models is marginal for this use case.

Singleton loading
-----------------
The model and exemplar embeddings are loaded ONCE at module import time (not
per detect() call).  This is the correct pattern for a module that may be
called thousands of times in a batch processing pipeline.  The module-level
`_MODEL` and `_EXEMPLAR_EMBEDDINGS` variables are the cached state.

Determinism
-----------
Cosine similarity in this space is deterministic for fixed inputs.  No
randomness is introduced anywhere in this detector.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import TYPE_CHECKING

import numpy as np

from risk_assessment.config import SEMANTIC_THRESHOLD
from risk_assessment.detectors.base import FieldDetector
from risk_assessment.exemplars import INJECTION_EXEMPLARS
from risk_assessment.results import DetectorResult

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

# Suppress symlink warning from huggingface_hub on Windows (cosmetic only)
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")

# ---------------------------------------------------------------------------
# Module-level singleton: model + pre-computed exemplar embeddings
# ---------------------------------------------------------------------------
# Loaded once on first access via _get_model().  Using lazy loading (not
# immediate module-level execution) so that importing this module in a test
# environment that has no network access does not fail — the model is already
# cached locally after the first download.

_MODEL: "SentenceTransformer | None" = None
_EXEMPLAR_EMBEDDINGS: "np.ndarray | None" = None  # shape: (n_exemplars, 384)
_EXEMPLAR_LIST: list[str] = list(INJECTION_EXEMPLARS)


def _get_model() -> "SentenceTransformer":
    """
    Return the cached SentenceTransformer model, loading it on first call.
    Thread-safe in CPython (GIL protects module-level assignment).
    """
    global _MODEL, _EXEMPLAR_EMBEDDINGS
    if _MODEL is None:
        from sentence_transformers import SentenceTransformer  # type: ignore

        logger.debug("Loading all-MiniLM-L6-v2 (first call — may take a moment)...")
        _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
        # Pre-compute exemplar embeddings once; shape: (n_exemplars, 384)
        _EXEMPLAR_EMBEDDINGS = _MODEL.encode(
            _EXEMPLAR_LIST,
            normalize_embeddings=True,  # L2-normalised → dot-product == cosine
            show_progress_bar=False,
        )
        logger.debug(
            "all-MiniLM-L6-v2 loaded. "
            f"Exemplar embeddings shape: {_EXEMPLAR_EMBEDDINGS.shape}"
        )
    return _MODEL


def _cosine_similarity_matrix(
    query_emb: "np.ndarray",    # shape: (1, d)
    corpus_embs: "np.ndarray",  # shape: (n, d)
) -> "np.ndarray":
    """
    Compute cosine similarities between a single query and a corpus of vectors.

    Both inputs must be L2-normalised (guaranteed when
    `normalize_embeddings=True` is passed to `model.encode()`), so cosine
    similarity reduces to the dot product.

    Returns shape (n,) — one similarity per corpus vector.
    """
    # Both are already unit-normalised; dot product == cosine similarity.
    return (corpus_embs @ query_emb.T).squeeze(axis=-1)


class SemanticDetector(FieldDetector):
    """
    Embedding-based FieldDetector.

    Computes cosine similarity between the evidence text embedding and each
    pre-computed exemplar embedding.  Returns the maximum similarity and the
    closest exemplar phrase as the hit explanation.

    The model and exemplar embeddings are loaded once (module-level singleton)
    and reused across all `detect()` calls — no per-call model loading.
    """

    @property
    def name(self) -> str:
        return "SemanticDetector"

    def detect(
        self,
        normalized_text: str,
        decoded_candidates: list[str],
    ) -> DetectorResult:
        """
        Embed `normalized_text` (and any decoded candidates), compute cosine
        similarity against all exemplar embeddings, and return the result.

        A match is declared when max_similarity >= SEMANTIC_THRESHOLD.
        The score IS the max cosine similarity (in [0.0, 1.0]).

        Parameters
        ----------
        normalized_text : str
            The normalized evidence field text.
        decoded_candidates : list[str]
            Additional strings to check (e.g. decoded base64).

        Returns
        -------
        DetectorResult
        """
        model = _get_model()

        # Collect all texts to embed: normalized text + any decoded candidates
        texts_to_check: list[tuple[str, str]] = [
            ("normalized_text", normalized_text)
        ] + [
            (f"decoded_candidate[{i}]", c)
            for i, c in enumerate(decoded_candidates)
        ]

        best_score: float = 0.0
        best_exemplar: str = ""
        best_source: str = ""

        for source_label, text in texts_to_check:
            if not text.strip():
                continue

            # Embed query; normalize_embeddings=True → unit vector
            query_emb: np.ndarray = model.encode(
                [text],
                normalize_embeddings=True,
                show_progress_bar=False,
            )  # shape: (1, 384)

            # Cosine similarities vs all exemplars; shape: (n_exemplars,)
            sims: np.ndarray = _cosine_similarity_matrix(
                query_emb, _EXEMPLAR_EMBEDDINGS
            )

            max_idx: int = int(np.argmax(sims))
            max_sim: float = float(sims[max_idx])

            if max_sim > best_score:
                best_score = max_sim
                best_exemplar = _EXEMPLAR_LIST[max_idx]
                best_source = source_label

        # Clamp to [0, 1] — cosine similarity can be very slightly > 1 due to
        # floating-point arithmetic in the dot product.
        best_score = min(1.0, max(0.0, best_score))

        if best_score >= SEMANTIC_THRESHOLD:
            return DetectorResult(
                detector=self.name,
                score=round(best_score, 6),
                matches=[best_exemplar],
                confidence=round(best_score, 6),  # similarity IS the confidence
                explanation=[
                    f"Semantic similarity {best_score:.4f} >= threshold "
                    f"{SEMANTIC_THRESHOLD} in {best_source}.",
                    f"Closest exemplar: '{best_exemplar}'.",
                    "This score reflects meaning-level similarity, not literal "
                    "word overlap — paraphrases of injection phrases are captured.",
                ],
            )

        return DetectorResult(
            detector=self.name,
            score=round(best_score, 6),
            matches=[],
            confidence=round(best_score, 6),
            explanation=[
                f"Maximum semantic similarity {best_score:.4f} < threshold "
                f"{SEMANTIC_THRESHOLD}; no injection phrase similarity detected.",
            ],
        )
