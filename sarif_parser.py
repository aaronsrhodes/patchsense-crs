"""SARIF 2.1.0 parser for PatchSense OSS-CRS integration.

Extracts vulnerability context (CWE, file, function, line, description) from
bug-candidate SARIF files emitted by detection CRSs in the exchange directory.

OSS-CRS bug-candidates use SARIF 2.1.0. Two formats encountered in practice:
  1. Static-analysis format: CWE as ruleId, description in message.text
  2. Fuzzer/ASan format: CWE in ruleId, ASan crash output in message.text
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VulnContext:
    """Extracted vulnerability context from a bug-candidate SARIF."""
    cwe: str               # e.g. "CWE-476" or "" if not found
    file_path: str         # source file path (relative to project root)
    function_name: str     # function where vulnerability occurs (or "")
    start_line: int        # line number (or 0 if not found)
    description: str       # vulnerability description for LLM prompt
    tool_name: str         # name of the detection tool
    rule_id: str           # raw ruleId from SARIF (may be CWE-XXX or short id)


def parse_sarif(sarif_path: Path) -> list[VulnContext]:
    """Parse a SARIF 2.1.0 file and extract all vulnerability contexts.

    Returns a list (one entry per result) for multi-finding SARIFs.
    Returns empty list if file is invalid or contains no results.
    """
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    results: list[VulnContext] = []

    for run in data.get("runs", []):
        tool_name = _extract_tool_name(run)
        rules = _build_rules_map(run)

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            cwe = _resolve_cwe(rule_id, rules)
            description = _build_description(result, rules, rule_id)

            # Extract primary location
            locations = result.get("locations", [])
            file_path = ""
            function_name = ""
            start_line = 0

            if locations:
                loc = locations[0]
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                file_path = artifact.get("uri", "")
                region = phys.get("region", {})
                start_line = int(region.get("startLine", 0))

                # Logical location (function name)
                logical = loc.get("logicalLocations", [])
                if logical:
                    function_name = logical[0].get("name", "")

                # Also check for function in ASan crash output in message.text
                if not function_name:
                    function_name = _extract_function_from_asan(
                        result.get("message", {}).get("text", ""), file_path
                    )

            results.append(VulnContext(
                cwe=cwe,
                file_path=file_path,
                function_name=function_name,
                start_line=start_line,
                description=description,
                tool_name=tool_name,
                rule_id=rule_id,
            ))

    return results


def match_sarif_to_diff(
    sarifs: list[VulnContext],
    diff_text: str,
) -> VulnContext | None:
    """Find the best-matching SARIF context for a given patch diff.

    Matches by file path appearing in the diff's +++ lines.
    Returns the first match, or the first SARIF entry if no path match.
    """
    if not sarifs:
        return None

    # Extract files modified by the patch
    patched_files: set[str] = set()
    for line in diff_text.splitlines():
        if line.startswith("+++ b/") or line.startswith("+++ "):
            path = line.removeprefix("+++ b/").removeprefix("+++ ").strip()
            if path != "/dev/null":
                patched_files.add(path)

    # Exact match: SARIF file path ends with a patched file or vice versa
    for sarif in sarifs:
        for patched in patched_files:
            if sarif.file_path.endswith(patched) or patched.endswith(sarif.file_path):
                return sarif

    # Filename-only match
    for sarif in sarifs:
        sarif_name = Path(sarif.file_path).name
        for patched in patched_files:
            if Path(patched).name == sarif_name:
                return sarif

    # Fallback: return first SARIF
    return sarifs[0]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_tool_name(run: dict) -> str:
    return run.get("tool", {}).get("driver", {}).get("name", "unknown")


def _build_rules_map(run: dict) -> dict[str, dict]:
    """Build a ruleId -> rule metadata mapping from the SARIF run."""
    rules: dict[str, dict] = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
        rule_id = rule.get("id", "")
        if rule_id:
            rules[rule_id] = rule
    return rules


_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _resolve_cwe(rule_id: str, rules: dict[str, dict]) -> str:
    """Extract a normalized CWE-XXX from ruleId or rule metadata."""
    # Direct CWE in ruleId
    m = _CWE_RE.search(rule_id)
    if m:
        return m.group().upper()

    # Check rule shortDescription or fullDescription
    rule = rules.get(rule_id, {})
    for field in ("shortDescription", "fullDescription"):
        text = rule.get(field, {}).get("text", "")
        m = _CWE_RE.search(text)
        if m:
            return m.group().upper()

    # Check helpUri for CWE reference
    uri = rule.get("helpUri", "")
    m = _CWE_RE.search(uri)
    if m:
        return m.group().upper()

    return ""


def _build_description(result: dict, rules: dict[str, dict], rule_id: str) -> str:
    """Build a human-readable vulnerability description for the LLM prompt."""
    parts: list[str] = []

    rule = rules.get(rule_id, {})
    short_desc = rule.get("shortDescription", {}).get("text", "")
    full_desc = rule.get("fullDescription", {}).get("text", "")
    message = result.get("message", {}).get("text", "")

    if short_desc:
        parts.append(short_desc)
    if full_desc and full_desc != short_desc:
        parts.append(full_desc)

    # Include crash output (ASan, etc.) but truncate to avoid prompt overflow
    if message and message not in parts:
        # Trim long ASan outputs to first 1500 chars
        if len(message) > 1500:
            message = message[:1500] + "\n... [truncated]"
        parts.append(message)

    return "\n".join(parts) if parts else f"Vulnerability detected by rule {rule_id}"


_ASAN_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-f]+\s+in\s+(\w+)\s+([^\s:]+):(\d+)",
    re.IGNORECASE,
)


def _extract_function_from_asan(crash_output: str, file_path: str) -> str:
    """Extract function name from an ASan stack trace matching the reported file."""
    target_name = Path(file_path).name if file_path else ""
    for match in _ASAN_FRAME_RE.finditer(crash_output):
        func_name = match.group(1)
        frame_file = match.group(2)
        # Skip fuzzer harness frames
        if func_name in ("LLVMFuzzerTestOneInput", "fuzzerTestOneInput"):
            continue
        # Prefer frames that match our reported file
        if target_name and target_name in frame_file:
            return func_name
    # Return first non-harness frame as fallback
    for match in _ASAN_FRAME_RE.finditer(crash_output):
        func_name = match.group(1)
        if func_name not in ("LLVMFuzzerTestOneInput", "fuzzerTestOneInput"):
            return func_name
    return ""
