"""Vulnerability detection pipeline.

Scans source code for vulnerability patterns, confirms with LLM analysis,
and generates proof artifacts + fix suggestions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from patchsense.models import (
    FamilyProfile,
    FixSuggestion,
    PatchClass,
    ProofArtifact,
    VulnerabilityCandidate,
    VulnerabilityReport,
)
from patchsense.taxonomy import classify_family, FAMILY_DESCRIPTIONS, CWE_FAMILIES
from patchsense.analyzer.source_patterns import (
    SourceAnalysisResult,
    SourceVulnIndicator,
    extract_source_patterns,
)
from patchsense.analyzer.suggest import load_family_profile
from patchsense.backends.base import LLMBackend


# Map source patterns to likely vulnerability families
_PATTERN_TO_FAMILIES: dict[str, list[str]] = {
    "missing_length_check": ["buffer-overflow"],
    "fixed_buffer_with_variable_input": ["buffer-overflow"],
    "unchecked_null_deref": ["null-deref", "use-after-free"],
    "uninitialized_use": ["uninitialized"],
    "missing_error_handling": ["resource-mgmt", "other"],
    "dangerous_type_narrowing": ["integer-overflow"],
    "unchecked_array_access": ["buffer-overflow", "integer-overflow"],
    "use_after_free": ["use-after-free", "double-free"],
    "missing_sanitization": ["injection"],
    "missing_input_validation": ["injection", "path-traversal"],
    "path_traversal": ["path-traversal"],
    "command_injection": ["injection"],
}


_DETECT_SYSTEM_PROMPT = (
    "You are a vulnerability researcher. Given a code snippet flagged by "
    "static analysis, determine whether it contains an exploitable vulnerability. "
    "Be precise: distinguish real vulnerabilities from false positives. "
    "Respond with ONLY a JSON object."
)

_DETECT_USER_TEMPLATE = """\
Static analysis flagged this code region as a potential {family} vulnerability.

=== VULNERABILITY FAMILY ===
{family_description}

=== FLAGGED CODE ===
File: {file_path}
Lines {start_line}-{end_line}:
```
{code_snippet}
```

=== ANALYSIS FLAGS ===
{flags}

=== FAMILY FIX PROFILE ===
Root-cause fixes for {family} vulnerabilities typically exhibit:
{fix_profile}

=== TASK ===
1. Is this actually exploitable? Consider whether the flagged patterns represent a real vulnerability or a false positive.
2. If vulnerable, describe the attack scenario.
3. Suggest a root-cause fix (not a symptom suppression).

Respond with ONLY:
{{"is_vulnerable": true/false, "confidence": 0.0-1.0, "description": "explanation", "cwe": "CWE-XXX", "suggested_fix": "brief description of root-cause fix", "suggested_diff": "unified diff if possible, or empty string"}}"""


_PROOF_SYSTEM_PROMPT = (
    "You are a security test engineer. Given a confirmed vulnerability, "
    "generate a minimal test case that demonstrates the vulnerability."
)

_PROOF_USER_TEMPLATE = """\
A {family} vulnerability was confirmed in this code:

=== CODE ===
File: {file_path}
```
{code_snippet}
```

=== VULNERABILITY ===
{description}
CWE: {cwe}

=== SUGGESTED FIX ===
{suggested_fix}

=== TASK ===
Generate a minimal test case that:
1. Triggers the vulnerability on the unpatched code (causes crash, OOB, or incorrect behavior)
2. Passes correctly on patched code

Output ONLY a JSON object:
{{"test_code": "the complete test case code", "language": "c or java", "description": "what the test demonstrates"}}"""


def detect_vulnerabilities(
    source: str,
    file_path: str = "",
    family: str | None = None,
    backend: LLMBackend | None = None,
    *,
    invariants_path: Path | None = None,
    confirm_with_llm: bool = True,
) -> VulnerabilityReport:
    """Scan source code for vulnerabilities.

    Args:
        source: Source code text.
        file_path: Path to source file.
        family: Restrict detection to a specific family (or None for all).
        backend: LLM backend for confirmation (required if confirm_with_llm=True).
        invariants_path: Override path to family_invariants.json.
        confirm_with_llm: Whether to use LLM to confirm candidates.

    Returns:
        VulnerabilityReport with candidates, proofs, and suggested fixes.
    """
    # Step 1: Source pattern extraction
    analysis = extract_source_patterns(source, file_path)

    if not analysis.indicators:
        return VulnerabilityReport(
            source_file=file_path,
            language=analysis.language,
        )

    # Step 2: Group indicators by proximity and family
    candidates: list[VulnerabilityCandidate] = []
    grouped = analysis.indicators_by_function()

    for region_name, indicators in grouped.items():
        # Determine applicable families from indicator patterns
        family_votes: dict[str, int] = {}
        for ind in indicators:
            for fam in _PATTERN_TO_FAMILIES.get(ind.pattern, []):
                family_votes[fam] = family_votes.get(fam, 0) + 1

        if family and family not in family_votes:
            continue  # skip regions that don't match requested family

        # Pick the most likely family
        if family:
            target_family = family
        elif family_votes:
            target_family = max(family_votes, key=family_votes.get)
        else:
            continue

        # Require ≥2 indicators for the candidate (noise filter)
        if len(indicators) < 2:
            continue

        line_nums = [ind.line_number for ind in indicators]
        min_line = min(line_nums)
        max_line = max(line_nums)

        # Extract code snippet
        lines = source.split("\n")
        snippet_start = max(0, min_line - 5)
        snippet_end = min(len(lines), max_line + 10)
        code_snippet = "\n".join(
            f"{i + snippet_start + 1:4d}: {lines[i + snippet_start]}"
            for i in range(snippet_end - snippet_start)
        )

        flags = "\n".join(
            f"  - {ind.pattern}: {ind.description} (line {ind.line_number})"
            for ind in indicators
        )

        candidate = VulnerabilityCandidate(
            file_path=file_path,
            function_name=region_name,
            line_range=(min_line, max_line),
            family=target_family,
            source_patterns=[ind.pattern for ind in indicators],
            confidence=0.5,  # provisional — LLM confirms
            description=f"Potential {target_family}: {len(indicators)} indicators",
        )

        # Step 3: LLM confirmation
        if confirm_with_llm and backend:
            profile = load_family_profile(target_family, invariants_path)
            fix_profile = _build_fix_profile(profile)

            user_prompt = _DETECT_USER_TEMPLATE.format(
                family=target_family,
                family_description=FAMILY_DESCRIPTIONS.get(target_family, ""),
                file_path=file_path,
                start_line=min_line,
                end_line=max_line,
                code_snippet=code_snippet[:2000],
                flags=flags,
                fix_profile=fix_profile,
            )

            try:
                raw = backend.complete(_DETECT_SYSTEM_PROMPT, user_prompt, max_tokens=1024)
                match = re.search(r"\{.*\}", raw, re.DOTALL)
                if match:
                    resp = json.loads(match.group())
                    if not resp.get("is_vulnerable", False):
                        continue  # LLM says false positive — skip

                    candidate.confidence = float(resp.get("confidence", 0.5))
                    candidate.description = resp.get("description", candidate.description)
                    candidate.cwe = resp.get("cwe", "")
            except (json.JSONDecodeError, ValueError, TypeError):
                pass  # keep provisional candidate

        candidates.append(candidate)

    # Step 4: Generate proofs and fix suggestions for confirmed candidates
    proofs: list[ProofArtifact] = []
    fixes: list[FixSuggestion] = []

    for candidate in candidates:
        if candidate.confidence >= 0.6:
            # Structural proof
            proofs.append(ProofArtifact(
                proof_type="structural",
                description=(
                    f"Source code analysis detected {len(candidate.source_patterns)} "
                    f"vulnerability indicators for {candidate.family}: "
                    f"{', '.join(candidate.source_patterns)}. "
                    f"LLM confirmed with {candidate.confidence:.0%} confidence."
                ),
            ))

            # Generate test case proof if we have a backend
            if backend:
                proof = _generate_test_proof(
                    candidate, source, file_path, backend
                )
                if proof:
                    proofs.append(proof)

    return VulnerabilityReport(
        source_file=file_path,
        language=analysis.language,
        candidates=candidates,
        proofs=proofs,
        suggested_fixes=fixes,
    )


def _build_fix_profile(profile: FamilyProfile) -> str:
    """Build a fix profile string from a FamilyProfile."""
    parts = []
    if profile.disjunctive_invariant:
        parts.append(f"  Typical patterns: {', '.join(profile.disjunctive_invariant)}")
    if profile.strong_fix_signals:
        parts.append(f"  Strong signals: {', '.join(profile.strong_fix_signals)}")
    if profile.anti_patterns:
        parts.append(f"  Avoid (suppression patterns): {', '.join(profile.anti_patterns)}")
    return "\n".join(parts) or "  No specific profile available."


def _generate_test_proof(
    candidate: VulnerabilityCandidate,
    source: str,
    file_path: str,
    backend: LLMBackend,
) -> ProofArtifact | None:
    """Generate a test case that demonstrates the vulnerability."""
    lines = source.split("\n")
    start = max(0, candidate.line_range[0] - 10)
    end = min(len(lines), candidate.line_range[1] + 20)
    code_snippet = "\n".join(lines[start:end])

    user_prompt = _PROOF_USER_TEMPLATE.format(
        family=candidate.family,
        file_path=file_path,
        code_snippet=code_snippet[:2000],
        description=candidate.description,
        cwe=candidate.cwe,
        suggested_fix="Address the root cause by adding proper validation/checks.",
    )

    try:
        raw = backend.complete(_PROOF_SYSTEM_PROMPT, user_prompt, max_tokens=1024)
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            resp = json.loads(match.group())
            return ProofArtifact(
                proof_type="test-case",
                description=resp.get("description", "LLM-generated vulnerability test"),
                test_code=resp.get("test_code", ""),
            )
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return None
