"""Core data models for PatchSense."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class InfoLevel(str, Enum):
    """How much vulnerability context to provide to the LLM."""
    BLIND = "blind"        # Only the diff — no vuln description, no CWE
    MINIMAL = "minimal"    # Short one-line hint + no CWE
    FULL = "full"          # Full description + CWE (default)


class PatchClass(str, Enum):
    """Classification of a patch's semantic intent."""
    ROOT_CAUSE_FIX = "root-cause-fix"
    SYMPTOM_SUPPRESSION = "symptom-suppression"
    UNRELATED = "unrelated"
    UNCERTAIN = "uncertain"


class PatchCategory(str, Enum):
    """Structural category of the change made by a patch."""
    NULL_CHECK = "null-check"
    BOUNDS_CHECK = "bounds-check"
    TYPE_CAST = "type-cast"
    MEMORY_MANAGEMENT = "memory-mgmt"
    LOGIC_CHANGE = "logic-change"
    ERROR_HANDLING = "error-handling"
    INPUT_VALIDATION = "input-validation"
    INITIALIZATION = "initialization"
    OTHER = "other"


class Hunk(BaseModel):
    """A single changed region in a unified diff."""
    file_path: str
    start_line_original: int
    start_line_patched: int
    removed_lines: list[str]
    added_lines: list[str]
    context_before: list[str] = Field(default_factory=list)
    context_after: list[str] = Field(default_factory=list)


class ParsedPatch(BaseModel):
    """A parsed unified diff with extracted structural information."""
    raw_diff: str
    hunks: list[Hunk]
    files_changed: list[str]
    lines_added: int
    lines_removed: int
    summary: str = ""


class RootCauseAnalysis(BaseModel):
    """Result of the Root Cause Extractor (Component 1)."""
    patch_category: PatchCategory
    changed_behavior: str
    category_confidence: float = Field(ge=0.0, le=1.0)
    structural_description: str
    functions_modified: list[str] = Field(default_factory=list)
    is_defensive_coding: bool = False


class AlignmentVerdict(BaseModel):
    """Result of the Vulnerability-Patch Alignment Verifier (Component 2)."""
    classification: PatchClass
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    risk_flags: list[str] = Field(default_factory=list)
    cwe_addressed: Optional[str] = None
    equivalent_exploits_likely_blocked: bool = False


class PatchSenseResult(BaseModel):
    """Final aggregated result from the full PatchSense pipeline."""
    patch_summary: str
    root_cause_analysis: RootCauseAnalysis
    alignment_verdict: AlignmentVerdict
    final_classification: PatchClass
    final_confidence: float = Field(ge=0.0, le=1.0)
    explanation: str

    @property
    def passed(self) -> bool:
        return self.final_classification == PatchClass.ROOT_CAUSE_FIX

    @property
    def failed(self) -> bool:
        return self.final_classification in (
            PatchClass.SYMPTOM_SUPPRESSION, PatchClass.UNRELATED
        )


# ============================================================================
# Phase 4 models: Invariants, Detection, Suggestion
# ============================================================================


class FamilyProfile(BaseModel):
    """Computed invariants and signals for a vulnerability family.

    Derived from training data pattern statistics. Used by detection,
    suggestion, and evaluation pipelines.
    """
    family: str
    min_examples: int = Field(
        description="Number of root-cause-fix examples this was derived from"
    )
    invariant_patterns: list[str] = Field(
        default_factory=list,
        description="Patterns present in >=90% of root-cause fixes",
    )
    strong_fix_signals: list[str] = Field(
        default_factory=list,
        description="Patterns with fix_rate >= 50% and fix:suppress ratio >= 3:1",
    )
    anti_patterns: list[str] = Field(
        default_factory=list,
        description="Patterns indicating symptom suppression",
    )
    disjunctive_invariant: list[str] = Field(
        default_factory=list,
        description="At least one must be present in a valid root-cause fix",
    )
    description: str = Field(
        default="",
        description="Natural language description of the vulnerability family",
    )


class FixSuggestion(BaseModel):
    """A suggested root-cause fix for a symptom-suppression patch."""
    original_classification: PatchClass
    family: str
    missing_fix_signals: list[str] = Field(default_factory=list)
    present_suppress_signals: list[str] = Field(default_factory=list)
    suggested_approach: str = ""
    suggested_diff: str = ""
    self_validation: Optional[PatchClass] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class VulnerabilityCandidate(BaseModel):
    """A potential vulnerability detected in source code."""
    file_path: str
    function_name: str = ""
    line_range: tuple[int, int] = (0, 0)
    family: str = ""
    cwe: str = ""
    source_patterns: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    description: str = ""


class ProofArtifact(BaseModel):
    """Proof of vulnerability or proof of fix."""
    proof_type: str = Field(
        description="'structural' or 'test-case'"
    )
    description: str = ""
    test_code: Optional[str] = None
    suggested_fix_diff: Optional[str] = None
    fix_validation: Optional[PatchClass] = None


class VulnerabilityReport(BaseModel):
    """Complete report from a detect/scan operation."""
    source_file: str
    language: str = ""
    candidates: list[VulnerabilityCandidate] = Field(default_factory=list)
    proofs: list[ProofArtifact] = Field(default_factory=list)
    suggested_fixes: list[FixSuggestion] = Field(default_factory=list)
