"""Component 2: Vulnerability-Patch Alignment Verifier.

This is the KEY novel contribution of PatchSense. Given the root-cause
analysis from Component 1, it reasons about whether the patch actually
addresses the vulnerability's root cause vs. suppresses symptoms.

Draws on the SoK paper's four failure mode categories:
  1. Symptom suppression (null guards, exception catches)
  2. Incomplete fixes (one path fixed, equivalent paths open)
  3. Functionality deviation (unintended semantic changes)
  4. Wrong root cause attribution
"""

from __future__ import annotations

import json
import re

from patchsense.backends.base import LLMBackend
from patchsense.models import (
    AlignmentVerdict,
    PatchClass,
    RootCauseAnalysis,
)
from patchsense.parser.diff import format_patch_for_llm, ParsedPatch
from patchsense.analyzer.fix_assignment import assess_fix_assignment, format_assessment_for_prompt
from patchsense.analyzer.location import analyze_patch_location, format_location_for_prompt
from patchsense.taxonomy import classify_family, FAMILY_DESCRIPTIONS


_SYSTEM_PROMPT = """\
You are an expert vulnerability researcher and code security auditor. You specialize in
determining whether a proposed code patch genuinely fixes the root cause of a security
vulnerability, or merely suppresses the symptoms (prevents a crash without fixing the
underlying defect).

You are aware of these four documented failure modes in AI-generated patches:
1. SYMPTOM SUPPRESSION: Adding null checks, exception handlers, or bounds guards that
   prevent the immediate crash but leave the root cause exploitable via other paths.
2. INCOMPLETE FIX: Correctly patching one triggering code path but leaving equivalent
   paths (same root cause, different call site) still vulnerable.
3. FUNCTIONALITY DEVIATION: The patch changes program behavior in ways unrelated or
   disproportionate to the fix, potentially introducing new bugs.
4. WRONG ROOT CAUSE: The patch modifies code near but not at the actual vulnerability;
   the fix is structurally unrelated to the defect described.

Be skeptical. AI systems generate plausible-looking patches that pass test suites while
failing on equivalent exploits. Your job is to catch these.
"""

_ALIGNMENT_PROMPT = """\
Assess whether this patch genuinely fixes the root cause of the described vulnerability.

=== VULNERABILITY ===
Description: {vuln_desc}
CWE: {cwe}

=== VULNERABILITY FAMILY CONTEXT ===
Family: {family}
{family_description}

=== PATCH LOCATION ANALYSIS (automated heuristic) ===
{location_context}

The location analysis detects WHERE the fix is applied. Use its guidance:
• remove-dangerous-op / return-value-fix / operation-reorder → HIGH CONFIDENCE root-cause
  fixes. Do NOT flag these as guard-without-root-fix or symptom-suppression.
• nullify-after-free / guard-at-vulnerability-site → VERIFY from context (see guidance
  in the detected pattern section above). These can be root-cause fixes or suppressions
  depending on whether the underlying operation is correct/intended.

=== FIX PATTERN ASSIGNMENT (empirical from training data) ===
{fix_assignment}

NOTE: The assignment above is empirical evidence from 800+ labeled CVE fixes —
it shows whether each pattern is statistically associated with fixes or suppressions
for this family. Use it as supporting evidence, not as a verdict. A pattern that is
a "fix signal" still needs to be applied AT the root cause to be a genuine fix;
applied elsewhere, even a fix-signal pattern can suppress symptoms.

=== ROOT CAUSE ANALYSIS (from static analysis) ===
Structural category: {patch_category}
What behavior changes: {changed_behavior}
Is this defensive/guard coding: {is_defensive}
Functions modified: {functions_modified}
Structural description: {structural_description}

=== PATCH DIFF ===
{patch_text}

=== ASSESSMENT TASK ===
Based on the above, determine:
1. Does the patch address the described vulnerability's root cause?
2. Or does it only add a defensive guard/check (symptom suppression)?
3. Are there equivalent code paths that remain vulnerable after this patch?
4. Does the patch introduce unintended behavioral changes?

Respond with a JSON object (no markdown, no code fences):
{{
  "classification": one of ["root-cause-fix", "symptom-suppression", "unrelated", "uncertain"],
  "confidence": float 0.0-1.0,
  "reasoning": "2-4 sentences explaining your verdict with specific references to the code",
  "risk_flags": ["list of specific risk flags, empty if none"],
  "cwe_addressed": "CWE-XXX if clearly addressed, null if not",
  "equivalent_exploits_likely_blocked": true or false
}}

Risk flags to consider (include any that apply):
- "guard-without-root-fix": adds check but root cause code path unchanged
- "single-path-fix": fixes one trigger but equivalent paths exist
- "off-by-one-incomplete": bounds check present but off-by-one in calculation
- "allocation-unchanged": check added at callsite but allocation size at root unchanged
- "exception-swallow": catches/suppresses the crash signal without fixing defect
- "semantic-drift": changes behavior beyond what the vulnerability fix requires
- "unrelated-location": modification is at a different location than root cause
"""


def verify_alignment(
    patch: ParsedPatch,
    root_cause: RootCauseAnalysis,
    vuln_description: str,
    cwe: str = "",
    backend: LLMBackend | None = None,
) -> AlignmentVerdict:
    """Run Component 2: assess whether the patch addresses the vulnerability root cause."""
    if backend is None:
        from patchsense.backends.factory import default_backend
        backend = default_backend()

    patch_text = format_patch_for_llm(patch)

    family = classify_family(cwe) if cwe else "unknown"
    family_description = FAMILY_DESCRIPTIONS.get(family, "")

    # Fix assignment: empirical pattern-to-family analysis
    fix_assess = assess_fix_assignment(patch.raw_diff, cwe)
    fix_assignment_text = format_assessment_for_prompt(fix_assess)

    # Location analysis: classify WHERE the fix is applied (canonical pattern detection)
    location_ctx = analyze_patch_location(patch)
    location_text = format_location_for_prompt(location_ctx)

    prompt = _ALIGNMENT_PROMPT.format(
        vuln_desc=vuln_description or "not provided — assess from code structure and patch content alone",
        cwe=cwe or "unspecified",
        family=family,
        family_description=family_description,
        location_context=location_text,
        fix_assignment=fix_assignment_text,
        patch_category=root_cause.patch_category.value,
        changed_behavior=root_cause.changed_behavior,
        is_defensive=root_cause.is_defensive_coding,
        functions_modified=", ".join(root_cause.functions_modified) or "unknown",
        structural_description=root_cause.structural_description,
        patch_text=patch_text,
    )

    raw = backend.complete(_SYSTEM_PROMPT, prompt, max_tokens=1024)
    data = _parse_json_response(raw)

    classification_str = data.get("classification", "uncertain")
    try:
        classification = PatchClass(classification_str)
    except ValueError:
        classification = PatchClass.UNCERTAIN

    # Heuristic: defensive coding patterns predict symptom suppression —
    # BUT only for families where defensive coding is NOT the canonical fix.
    # For buffer-overflow, null-deref, use-after-free, double-free, uninitialized,
    # and resource-mgmt, defensive coding (bounds checks, null checks) IS the fix.
    confidence = float(data.get("confidence", 0.5))
    _defensive_is_fix_families = {
        "buffer-overflow", "null-deref", "use-after-free",
        "double-free", "uninitialized", "resource-mgmt",
    }
    if (
        root_cause.is_defensive_coding
        and classification == PatchClass.ROOT_CAUSE_FIX
        and confidence < 0.85
        and family not in _defensive_is_fix_families
    ):
        classification = PatchClass.UNCERTAIN
        confidence = max(confidence - 0.15, 0.0)

    return AlignmentVerdict(
        classification=classification,
        confidence=confidence,
        reasoning=data.get("reasoning", ""),
        risk_flags=data.get("risk_flags") or [],
        cwe_addressed=data.get("cwe_addressed"),
        equivalent_exploits_likely_blocked=bool(
            data.get("equivalent_exploits_likely_blocked", False)
        ),
    )


def _parse_json_response(raw: str) -> dict:
    raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {}
