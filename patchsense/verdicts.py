"""Verdict aggregator — combines Component 1 and Component 2 results into a final verdict.

CWE-aware: For vulnerability families where defensive coding (bounds checks,
null checks, etc.) IS the canonical root-cause fix, the defensive-coding
penalty is suppressed. This prevents false downgrades on buffer-overflow,
null-deref, use-after-free, double-free, and uninitialized families.
"""

from __future__ import annotations

from patchsense.models import (
    AlignmentVerdict,
    ParsedPatch,
    PatchClass,
    PatchSenseResult,
    RootCauseAnalysis,
)
from patchsense.taxonomy import classify_family


# Patches classified as these structural categories are high-risk for symptom suppression
_HIGH_RISK_CATEGORIES = {"null-check", "bounds-check", "error-handling"}

# Families where defensive coding (guards, checks) IS the canonical root-cause fix.
# Derived from family_invariants.json: these families have adds_null_check,
# adds_bounds_check, adds_validation, adds_length_check as pure fix signals
# (fix_rate > 0, suppress_rate = 0) in their invariant patterns.
_DEFENSIVE_IS_FIX_FAMILIES = frozenset({
    "buffer-overflow",   # bounds/length checks ARE the fix (CWE-119/120/121/122/787)
    "null-deref",        # null checks ARE the fix (CWE-476)
    "use-after-free",    # null-after-free ARE the fix (CWE-416)
    "double-free",       # null-after-free ARE the fix (CWE-415)
    "uninitialized",     # initialization checks ARE the fix (CWE-457/908/909)
    "resource-mgmt",     # validation/error-handling ARE the fix (CWE-400/401/404/772)
})


def aggregate(
    patch: ParsedPatch,
    root_cause: RootCauseAnalysis,
    alignment: AlignmentVerdict,
    cwe: str = "",
) -> PatchSenseResult:
    """Combine Component 1 + 2 into a final PatchSenseResult."""
    final_class, final_confidence = _compute_final_verdict(
        root_cause, alignment, cwe=cwe
    )
    explanation = _build_explanation(patch, root_cause, alignment, final_class)

    return PatchSenseResult(
        patch_summary=patch.summary,
        root_cause_analysis=root_cause,
        alignment_verdict=alignment,
        final_classification=final_class,
        final_confidence=final_confidence,
        explanation=explanation,
    )


def _compute_final_verdict(
    root_cause: RootCauseAnalysis,
    alignment: AlignmentVerdict,
    cwe: str = "",
) -> tuple[PatchClass, float]:
    """Weighted ensemble of structural signals and LLM alignment verdict.

    CWE-aware: skips defensive-coding penalty for families where defensive
    coding IS the canonical root-cause fix (e.g., buffer-overflow, null-deref).
    """
    base_class = alignment.classification
    base_conf = alignment.confidence

    family = classify_family(cwe) if cwe else "unknown"
    defensive_is_fix = family in _DEFENSIVE_IS_FIX_FAMILIES

    # Signal 1: defensive-coding flag — context-dependent
    if root_cause.is_defensive_coding and not defensive_is_fix:
        # Only penalize defensive coding when it's NOT the canonical fix
        if base_class == PatchClass.ROOT_CAUSE_FIX:
            # Downgrade — defensive coding + LLM says fix = high uncertainty
            base_conf -= 0.10
        elif base_class == PatchClass.UNCERTAIN:
            # Resolve uncertainty toward symptom suppression
            base_class = PatchClass.SYMPTOM_SUPPRESSION
            base_conf = min(base_conf + 0.10, 0.75)

    # Signal 2: structural category risk
    if root_cause.patch_category.value in _HIGH_RISK_CATEGORIES:
        if base_class == PatchClass.ROOT_CAUSE_FIX:
            if not defensive_is_fix:
                base_conf -= 0.05  # slight penalty only for non-exempt families
            # For exempt families: no penalty — these categories ARE the fix

    # Signal 3: risk flags — filter out expected patterns for exempt families
    flags = alignment.risk_flags
    if defensive_is_fix:
        flags = [f for f in flags if f not in (
            "guard-without-root-fix", "allocation-unchanged"
        )]
    flag_penalty = len(flags) * 0.05
    base_conf = max(0.0, base_conf - flag_penalty)

    # Signal 4: if LLM says equivalent exploits NOT blocked but claims root-cause-fix, downgrade
    if (
        base_class == PatchClass.ROOT_CAUSE_FIX
        and not alignment.equivalent_exploits_likely_blocked
        and base_conf < 0.80
    ):
        base_class = PatchClass.UNCERTAIN
        base_conf -= 0.05

    final_conf = round(max(0.0, min(1.0, base_conf)), 3)
    return base_class, final_conf


def _build_explanation(
    patch: ParsedPatch,
    root_cause: RootCauseAnalysis,
    alignment: AlignmentVerdict,
    final_class: PatchClass,
) -> str:
    parts: list[str] = []

    # Verdict line
    verdict_label = {
        PatchClass.ROOT_CAUSE_FIX: "ROOT CAUSE FIX",
        PatchClass.SYMPTOM_SUPPRESSION: "SYMPTOM SUPPRESSION",
        PatchClass.UNRELATED: "UNRELATED CHANGE",
        PatchClass.UNCERTAIN: "UNCERTAIN",
    }[final_class]
    parts.append(f"Verdict: {verdict_label}")

    # Structural summary
    parts.append(
        f"Structural change: {root_cause.patch_category.value} "
        f"({'defensive guard' if root_cause.is_defensive_coding else 'logic change'}) "
        f"in {', '.join(root_cause.functions_modified) or 'unknown function(s)'}."
    )
    parts.append(f"Behavior changed: {root_cause.changed_behavior}")

    # LLM reasoning
    parts.append(f"Alignment assessment: {alignment.reasoning}")

    # Risk flags
    if alignment.risk_flags:
        parts.append("Risk flags: " + ", ".join(alignment.risk_flags))

    return "\n".join(parts)
