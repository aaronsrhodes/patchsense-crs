"""Fix Assignment Engine — determines whether observed patterns address the declared vulnerability.

Given a patch's structural patterns and the vulnerability's CWE family, this module
determines whether each pattern is a valid fix for that family or a suspicious
unassigned pattern.

Key insight: Many fix patterns (null checks, bounds checks, type changes) are
structurally identical to symptom suppressions. The difference is CONTEXT — whether
the pattern addresses the declared vulnerability's family or not. A null check
IS the fix for null-deref (CWE-476), but it's a suppression for buffer-overflow
(CWE-122) unless the overflow was caused by a null-derived size.

This module uses the empirical pattern_rates from family_invariants.json to make
this determination without hardcoding specific CVE fixes.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from patchsense.patterns import extract_diff_patterns, get_dominant_patterns, PATTERN_NAMES
from patchsense.taxonomy import classify_family, FAMILY_DESCRIPTIONS


class PatternRole(str, Enum):
    """Role of a structural pattern in the context of a specific vulnerability family."""
    FIX_SIGNAL = "fix-signal"           # Pure fix indicator (fix_rate > 0, suppress_rate = 0)
    STRONG_FIX = "strong-fix"           # Strong fix signal (fix_rate >= 3x suppress_rate)
    SUPPRESS_SIGNAL = "suppress-signal" # More common in suppressions than fixes
    AMBIGUOUS = "ambiguous"             # Present in both fixes and suppressions
    NEUTRAL = "neutral"                 # Low rates in both — not informative


class PatternAssignment(BaseModel):
    """Assignment of a single observed pattern to a vulnerability context."""
    pattern: str
    role: PatternRole
    fix_rate: float = 0.0
    suppress_rate: float = 0.0
    explanation: str = ""


class FixAssessment(BaseModel):
    """Complete assessment of whether the patch's patterns address the vulnerability."""
    family: str
    cwe: str = ""
    observed_patterns: list[str] = Field(default_factory=list)
    assignments: list[PatternAssignment] = Field(default_factory=list)
    fix_patterns: list[str] = Field(default_factory=list)
    suppress_patterns: list[str] = Field(default_factory=list)
    ambiguous_patterns: list[str] = Field(default_factory=list)
    unassigned_patterns: list[str] = Field(default_factory=list)
    fix_coverage: float = 0.0  # fraction of patterns that are fix signals
    suppress_coverage: float = 0.0  # fraction that are suppress signals
    assessment: str = ""  # human-readable summary


# Load family invariants (pattern_rates per family).
# family_invariants.json ships as package data inside patchsense/data/.
# importlib.resources resolves the path correctly after pip install.
def _invariants_path() -> Path:
    """Return the path to family_invariants.json, whether installed or in-dev."""
    try:
        import importlib.resources as pkg_resources
        ref = pkg_resources.files("patchsense.data") / "family_invariants.json"
        with pkg_resources.as_file(ref) as p:
            return Path(p)
    except (ModuleNotFoundError, TypeError):
        pass
    # Fallback for editable installs and legacy environments
    return Path(__file__).parent.parent.parent / "data" / "family_invariants.json"

_invariants: dict = {}


def _load_invariants() -> dict:
    """Load family invariants from disk (cached)."""
    global _invariants
    if not _invariants:
        path = _invariants_path()
        if path.exists():
            with open(path) as f:
                _invariants = json.load(f)
    return _invariants


def classify_pattern_role(
    pattern: str,
    family: str,
    fix_rate: float,
    suppress_rate: float,
) -> tuple[PatternRole, str]:
    """Determine a pattern's role for a given vulnerability family.

    Uses empirical fix/suppress rates from training data to classify
    each pattern as fix, suppress, ambiguous, or neutral.

    Returns (role, explanation).
    """
    # Pure fix signal: appears in fixes but never in suppressions
    if fix_rate > 0 and suppress_rate == 0:
        return (
            PatternRole.FIX_SIGNAL,
            f"{pattern} appears in {fix_rate:.0%} of {family} fixes and "
            f"never in suppressions — valid fix pattern for this family."
        )

    # Strong fix signal: fix_rate >= 3x suppress_rate
    if fix_rate > 0 and suppress_rate > 0 and fix_rate >= 3 * suppress_rate:
        return (
            PatternRole.STRONG_FIX,
            f"{pattern} appears in {fix_rate:.0%} of {family} fixes vs. "
            f"{suppress_rate:.0%} of suppressions — strong fix signal."
        )

    # Suppress signal: must be substantially more common in suppressions (>= 2x fix_rate)
    if suppress_rate >= 2 * fix_rate and suppress_rate > 0:
        return (
            PatternRole.SUPPRESS_SIGNAL,
            f"{pattern} appears in {suppress_rate:.0%} of {family} suppressions "
            f"vs. {fix_rate:.0%} of fixes — suppression indicator for this family."
        )

    # Ambiguous: both rates significant, neither dominates
    if fix_rate > 0 and suppress_rate > 0:
        return (
            PatternRole.AMBIGUOUS,
            f"{pattern} appears in both fixes ({fix_rate:.0%}) and suppressions "
            f"({suppress_rate:.0%}) for {family} — requires context to interpret."
        )

    # Neutral: low/zero rates in both
    return (
        PatternRole.NEUTRAL,
        f"{pattern} is rare in {family} (fix: {fix_rate:.0%}, "
        f"suppress: {suppress_rate:.0%}) — not informative for this family."
    )


def assess_fix_assignment(
    diff_text: str,
    cwe: str = "",
) -> FixAssessment:
    """Assess whether the patch's structural patterns address the declared vulnerability.

    This is the core fix-assignment algorithm:
    1. Extract structural patterns from the diff
    2. Look up the CWE family and its pattern rates
    3. For each observed pattern, classify its role for this family
    4. Determine which patterns are assigned (fix/suppress) vs. unassigned
    5. Produce a structured assessment

    Args:
        diff_text: Unified diff text
        cwe: CWE identifier (e.g., "CWE-122")

    Returns:
        FixAssessment with per-pattern assignments and overall assessment
    """
    family = classify_family(cwe) if cwe else "unknown"
    invariants = _load_invariants()
    family_data = invariants.get(family, {})
    pattern_rates = family_data.get("pattern_rates", {})
    anti_patterns = family_data.get("anti_patterns", [])

    # Extract structural patterns from the diff
    patterns = extract_diff_patterns(diff_text)
    observed = get_dominant_patterns(patterns)

    assignments: list[PatternAssignment] = []
    fix_patterns: list[str] = []
    suppress_patterns: list[str] = []
    ambiguous_patterns: list[str] = []
    unassigned_patterns: list[str] = []

    for p in observed:
        rates = pattern_rates.get(p, {})
        fix_rate = rates.get("fix_rate", 0.0)
        suppress_rate = rates.get("suppress_rate", 0.0)

        role, explanation = classify_pattern_role(p, family, fix_rate, suppress_rate)

        # Also check if it's a declared anti-pattern for this family
        if p in anti_patterns and role not in (PatternRole.SUPPRESS_SIGNAL,):
            role = PatternRole.SUPPRESS_SIGNAL
            explanation = (
                f"{p} is a declared anti-pattern for {family} "
                f"(statistically associated with symptom suppression)."
            )

        assignments.append(PatternAssignment(
            pattern=p,
            role=role,
            fix_rate=fix_rate,
            suppress_rate=suppress_rate,
            explanation=explanation,
        ))

        if role in (PatternRole.FIX_SIGNAL, PatternRole.STRONG_FIX):
            fix_patterns.append(p)
        elif role == PatternRole.SUPPRESS_SIGNAL:
            suppress_patterns.append(p)
        elif role == PatternRole.AMBIGUOUS:
            ambiguous_patterns.append(p)
        else:
            unassigned_patterns.append(p)

    # Compute coverage ratios
    total = len(observed) or 1
    fix_coverage = len(fix_patterns) / total
    suppress_coverage = len(suppress_patterns) / total

    # Build assessment summary
    assessment = _build_assessment(
        family, observed, fix_patterns, suppress_patterns,
        ambiguous_patterns, unassigned_patterns, fix_coverage, suppress_coverage,
    )

    return FixAssessment(
        family=family,
        cwe=cwe,
        observed_patterns=observed,
        assignments=assignments,
        fix_patterns=fix_patterns,
        suppress_patterns=suppress_patterns,
        ambiguous_patterns=ambiguous_patterns,
        unassigned_patterns=unassigned_patterns,
        fix_coverage=round(fix_coverage, 3),
        suppress_coverage=round(suppress_coverage, 3),
        assessment=assessment,
    )


def _build_assessment(
    family: str,
    observed: list[str],
    fix_patterns: list[str],
    suppress_patterns: list[str],
    ambiguous_patterns: list[str],
    unassigned_patterns: list[str],
    fix_coverage: float,
    suppress_coverage: float,
) -> str:
    """Build human-readable assessment of fix assignment."""
    parts: list[str] = []

    if not observed:
        return f"No structural patterns detected in patch for {family} family."

    if fix_patterns and not suppress_patterns:
        parts.append(
            f"All informative patterns ({', '.join(fix_patterns)}) are valid "
            f"fix signals for {family}. No suppression indicators detected."
        )
    elif suppress_patterns and not fix_patterns:
        parts.append(
            f"Patterns ({', '.join(suppress_patterns)}) are suppression "
            f"indicators for {family}. No fix signals detected. This patch "
            f"likely suppresses symptoms rather than fixing the root cause."
        )
    elif fix_patterns and suppress_patterns:
        parts.append(
            f"Mixed signals: {', '.join(fix_patterns)} are fix signals, but "
            f"{', '.join(suppress_patterns)} are suppression indicators for "
            f"{family}. The fix patterns address the vulnerability, but the "
            f"suppression patterns suggest incomplete or auxiliary changes."
        )
    else:
        parts.append(
            f"No clear fix or suppression signals for {family}. "
            f"Observed patterns are ambiguous or uninformative for this family."
        )

    if ambiguous_patterns:
        parts.append(
            f"Ambiguous patterns requiring context: {', '.join(ambiguous_patterns)}. "
            f"These appear in both fixes and suppressions for {family} — "
            f"their meaning depends on WHERE in the code they are applied."
        )

    return " ".join(parts)


def format_assessment_for_prompt(assessment: FixAssessment) -> str:
    """Format the fix assessment as context for the LLM alignment prompt.

    This is injected into the alignment prompt to give the LLM empirical
    evidence about whether the patch's patterns match fix or suppress
    profiles for the declared vulnerability family.
    """
    lines: list[str] = []
    lines.append(f"Family: {assessment.family}")
    lines.append(f"Observed patterns: {', '.join(assessment.observed_patterns) or 'none'}")
    lines.append("")

    if assessment.fix_patterns:
        lines.append(
            f"FIX SIGNALS for {assessment.family}: "
            f"{', '.join(assessment.fix_patterns)}"
        )
        for a in assessment.assignments:
            if a.role in (PatternRole.FIX_SIGNAL, PatternRole.STRONG_FIX):
                lines.append(f"  • {a.explanation}")

    if assessment.suppress_patterns:
        lines.append(
            f"SUPPRESSION SIGNALS for {assessment.family}: "
            f"{', '.join(assessment.suppress_patterns)}"
        )
        for a in assessment.assignments:
            if a.role == PatternRole.SUPPRESS_SIGNAL:
                lines.append(f"  • {a.explanation}")

    if assessment.ambiguous_patterns:
        lines.append(
            f"AMBIGUOUS (context-dependent): "
            f"{', '.join(assessment.ambiguous_patterns)}"
        )
        for a in assessment.assignments:
            if a.role == PatternRole.AMBIGUOUS:
                lines.append(f"  • {a.explanation}")

    lines.append("")
    lines.append(assessment.assessment)

    return "\n".join(lines)
