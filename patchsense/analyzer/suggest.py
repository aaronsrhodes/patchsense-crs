"""Fix suggestion engine — suggests root-cause fixes for symptom-suppression patches.

Given a patch classified as symptom-suppression, uses the family's invariant
profile to identify what structural patterns are missing and prompts the LLM
to generate a root-cause fix.
"""

from __future__ import annotations

import json
from pathlib import Path

from patchsense.models import (
    AlignmentVerdict,
    FixSuggestion,
    PatchClass,
    PatchSenseResult,
    RootCauseAnalysis,
    FamilyProfile,
    ParsedPatch,
)
from patchsense.taxonomy import classify_family, FAMILY_DESCRIPTIONS
from patchsense.patterns import extract_diff_patterns, get_dominant_patterns
from patchsense.backends.base import LLMBackend

# Default invariants path — resolves correctly whether installed or in dev tree.
def _default_invariants_path() -> Path:
    try:
        import importlib.resources as pkg_resources
        ref = pkg_resources.files("patchsense.data") / "family_invariants.json"
        with pkg_resources.as_file(ref) as p:
            return Path(p)
    except (ModuleNotFoundError, TypeError):
        pass
    return Path(__file__).parent.parent.parent / "data" / "family_invariants.json"

_INVARIANTS_PATH = _default_invariants_path()


def load_family_profile(family: str, invariants_path: Path | None = None) -> FamilyProfile:
    """Load a FamilyProfile from the invariants JSON file."""
    path = invariants_path or _INVARIANTS_PATH
    if not path.exists():
        return FamilyProfile(
            family=family,
            min_examples=0,
            description=FAMILY_DESCRIPTIONS.get(family, ""),
        )

    data = json.loads(path.read_text())
    if family not in data:
        return FamilyProfile(
            family=family,
            min_examples=0,
            description=FAMILY_DESCRIPTIONS.get(family, ""),
        )

    entry = data[family]
    return FamilyProfile(
        family=family,
        min_examples=entry.get("min_examples", 0),
        invariant_patterns=entry.get("invariant_patterns", []),
        strong_fix_signals=entry.get("strong_fix_signals", []),
        anti_patterns=entry.get("anti_patterns", []),
        disjunctive_invariant=entry.get("disjunctive_invariant", []),
        description=entry.get("description", FAMILY_DESCRIPTIONS.get(family, "")),
    )


_SYSTEM_PROMPT = (
    "You are a security engineer specializing in vulnerability remediation. "
    "Given a patch classified as symptom-suppression, your task is to suggest "
    "a root-cause fix that addresses the underlying vulnerability rather than "
    "masking its symptoms. Your suggestion must be a concrete unified diff."
)

_USER_TEMPLATE = """\
A patch for a {family} vulnerability has been classified as SYMPTOM-SUPPRESSION.

=== VULNERABILITY FAMILY ===
{family_description}

=== ORIGINAL PATCH (symptom-suppression) ===
{patch_text}

=== CLASSIFICATION ANALYSIS ===
{reasoning}
Risk flags: {risk_flags}

=== FAMILY FIX PROFILE ===
Root-cause fixes for {family} vulnerabilities typically exhibit these structural patterns:
{fix_profile}

This patch is MISSING these root-cause signals: {missing_signals}
This patch EXHIBITS these suppression signals: {suppress_signals}

=== TASK ===
Suggest a root-cause fix that addresses the structural patterns listed above.
Output ONLY a JSON object with these fields:
{{"suggested_diff": "unified diff replacing the symptom-suppression patch", "explanation": "why this addresses the root cause", "confidence": 0.0-1.0}}"""


def suggest_fix(
    parsed: ParsedPatch,
    result: PatchSenseResult,
    vuln_description: str,
    cwe: str,
    backend: LLMBackend,
    *,
    invariants_path: Path | None = None,
) -> FixSuggestion:
    """Suggest a root-cause fix for a patch classified as symptom-suppression.

    Args:
        parsed: The parsed original patch.
        result: The PatchSenseResult from the validate pipeline.
        vuln_description: Vulnerability description.
        cwe: CWE identifier.
        backend: LLM backend for generating the suggestion.
        invariants_path: Override path to family_invariants.json.

    Returns:
        FixSuggestion with the suggested approach and diff.
    """
    family = classify_family(cwe)
    profile = load_family_profile(family, invariants_path)

    # Extract current patch patterns
    current_patterns = extract_diff_patterns(parsed.raw_diff)
    present = set(get_dominant_patterns(current_patterns))

    # Determine missing fix signals and present suppression signals
    missing = [p for p in profile.disjunctive_invariant if p not in present]
    if not missing:
        missing = [p for p in profile.strong_fix_signals if p not in present]

    suppress_present = [p for p in profile.anti_patterns if p in present]

    # Build fix profile string
    fix_profile_parts = []
    if profile.disjunctive_invariant:
        fix_profile_parts.append(
            f"  Disjunctive invariant (at least one required): "
            f"{', '.join(profile.disjunctive_invariant)}"
        )
    if profile.strong_fix_signals:
        fix_profile_parts.append(
            f"  Strong fix signals: {', '.join(profile.strong_fix_signals)}"
        )
    if profile.anti_patterns:
        fix_profile_parts.append(
            f"  Suppression anti-patterns to avoid: {', '.join(profile.anti_patterns)}"
        )
    fix_profile = "\n".join(fix_profile_parts) or "  No specific profile available."

    # Build prompt
    user_prompt = _USER_TEMPLATE.format(
        family=family,
        family_description=profile.description or FAMILY_DESCRIPTIONS.get(family, ""),
        patch_text=parsed.raw_diff[:3000],  # truncate large diffs
        reasoning=result.alignment_verdict.reasoning,
        risk_flags=", ".join(result.alignment_verdict.risk_flags) or "none",
        fix_profile=fix_profile,
        missing_signals=", ".join(missing) or "none identified",
        suppress_signals=", ".join(suppress_present) or "none identified",
    )

    # Call LLM
    raw = backend.complete(_SYSTEM_PROMPT, user_prompt, max_tokens=2048)

    # Parse response
    suggested_diff = ""
    explanation = ""
    confidence = 0.0

    try:
        import re
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            resp = json.loads(match.group())
            suggested_diff = resp.get("suggested_diff", "")
            explanation = resp.get("explanation", "")
            confidence = float(resp.get("confidence", 0.0))
        else:
            # No JSON structure found — use raw response as fallback
            explanation = raw[:500]
    except (json.JSONDecodeError, ValueError, TypeError):
        explanation = raw[:500]  # fallback: use raw response as explanation

    return FixSuggestion(
        original_classification=result.final_classification,
        family=family,
        missing_fix_signals=missing,
        present_suppress_signals=suppress_present,
        suggested_approach=explanation,
        suggested_diff=suggested_diff,
        self_validation=None,  # populated by verify_suggestion() if called
        confidence=confidence,
    )


def verify_suggestion(
    suggestion: FixSuggestion,
    vuln_description: str,
    cwe: str,
    backend: LLMBackend,
) -> FixSuggestion:
    """Re-run the PatchSense pipeline on a suggested fix to self-validate.

    If the suggestion classifies as root-cause-fix, confidence increases.
    If it classifies as symptom-suppression, the suggestion is flagged.
    """
    if not suggestion.suggested_diff:
        return suggestion

    # Lazy import to avoid circular dependency
    from patchsense.parser.diff import parse_patch
    from patchsense.parser.ast_diff import extract_ast_diff
    from patchsense.analyzer.root_cause import extract_root_cause
    from patchsense.analyzer.alignment import verify_alignment
    from patchsense.verdicts import aggregate

    try:
        parsed = parse_patch(suggestion.suggested_diff)
        ast_diff = extract_ast_diff(parsed, None)
        root_cause = extract_root_cause(parsed, ast_diff, vuln_description, cwe, backend)
        alignment = verify_alignment(parsed, root_cause, vuln_description, cwe, backend)
        result = aggregate(parsed, root_cause, alignment)
        suggestion.self_validation = result.final_classification
    except Exception:
        suggestion.self_validation = PatchClass.UNCERTAIN

    return suggestion
