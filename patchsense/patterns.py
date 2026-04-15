"""Structural diff pattern extraction.

Extracts 15 boolean structural patterns from unified diffs that indicate
the type of change a patch makes. These patterns are the foundation for:
  - Patch classification (root-cause-fix vs symptom-suppression)
  - Family invariant computation
  - Training data generation
  - Vulnerability detection (inverted as absence-of-pattern indicators)
"""

from __future__ import annotations

import re


# All extractable pattern names (the 15 boolean patterns)
PATTERN_NAMES = [
    "adds_null_check",
    "adds_bounds_check",
    "adds_length_check",
    "changes_allocation",
    "adds_return_early",
    "removes_code",
    "adds_error_handling",
    "changes_type",
    "adds_validation",
    "removes_backdoor",
    "fixes_off_by_one",
    "adds_initialization",
    "changes_loop_bound",
    "adds_sanitization",
    "changes_comparison",
]

# Human-readable descriptions per pattern
PATTERN_DESCRIPTIONS: dict[str, str] = {
    "adds_null_check": "adds null/nullptr check before use",
    "adds_bounds_check": "adds numeric bounds check (comparison against limit)",
    "adds_length_check": "adds length/size validation",
    "changes_allocation": "modifies memory allocation (malloc/calloc/realloc/new)",
    "adds_return_early": "adds early return on error/null/invalid state",
    "removes_code": "net code removal (more lines deleted than added)",
    "adds_error_handling": "adds try/catch or error logging",
    "changes_type": "changes variable/parameter type (e.g., int→size_t)",
    "adds_validation": "adds input validation or assertion",
    "removes_backdoor": "removes suspicious exec/system call",
    "fixes_off_by_one": "adjusts boundary by ±1 (off-by-one fix)",
    "adds_initialization": "adds variable initialization (= 0, = null, memset)",
    "changes_loop_bound": "modifies loop condition or iteration bound",
    "adds_sanitization": "adds input escaping/encoding/sanitization",
    "changes_comparison": "modifies comparison operator or operands",
}


def extract_diff_patterns(diff_text: str) -> dict:
    """Extract structural patterns from a unified diff.

    Returns a dict with:
      - 15 boolean pattern flags
      - total_added: number of added lines
      - total_removed: number of removed lines
    """
    patterns = {name: False for name in PATTERN_NAMES}
    patterns["total_added"] = 0
    patterns["total_removed"] = 0

    added_lines = []
    removed_lines = []

    for line in diff_text.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed_lines.append(line[1:].strip())

    patterns["total_added"] = len(added_lines)
    patterns["total_removed"] = len(removed_lines)

    added_text = "\n".join(added_lines).lower()
    removed_text = "\n".join(removed_lines).lower()

    # Null checks
    if re.search(r'if\s*\(.+==\s*null|if\s*\(.+!=\s*null|if\s*\(\s*!\s*\w+\s*\)', added_text):
        patterns["adds_null_check"] = True

    # Bounds checks (comparisons against numeric limits, sizes, capacity variables, or macros)
    # Note: added_text is lowercased, so match lowercase versions of macros
    if re.search(
        r'if\s*\(.+[<>]=?\s*\d+|'              # if (x < 100)
        r'if\s*\(.+[<>]=?\s*\w*(size|len|cap|count|max|alloc|limit)\w*|'  # if (x < nAlloc/capacity)
        r'\.len(gth)?\s*[<>]|'                  # .length > N
        r'\breturn_error_if\s*\([^,]+[<>][^,]+,|'  # RETURN_ERROR_IF(x < y, ...) macro
        r'\bassert\s*\([^)]+[<>][^)]+\)|'       # assert(x < y)
        r'if\s*\(.+[<>]=?\s*(size_max|int\d*_m[ai][xn]|uint\d*_max|llong_max|ssize_max)|'
        r'if\s*\(.+==\s*(int\d*_m[ai][xn]|uint\d*_max|size_max)',  # if (n == INT32_MIN)
        added_text,
    ):
        patterns["adds_bounds_check"] = True

    # Length checks
    if re.search(r'strlen|\.length|\.len\b|\.size\(\)', added_text):
        patterns["adds_length_check"] = True

    # Allocation changes — require actual allocation function call syntax (avoid
    # false positives on variable names like nAlloc, myAllocator, etc.)
    _ALLOC_CALL = r'\b(m|c|re|g_|k|ngx_p[cn]?)?alloc\s*\(|new\s+\w+[\[\(]'
    if re.search(_ALLOC_CALL, added_text):
        if re.search(_ALLOC_CALL, removed_text):
            patterns["changes_allocation"] = True
        elif not re.search(_ALLOC_CALL, removed_text):
            patterns["changes_allocation"] = True

    # Early return (covers literal ints, NULL, false, error macros like -EINVAL/-ENODEV)
    if re.search(r'return\s+(-?\d+|null|false|err\w*|-[A-Z]\w+|ngx_error|ngx_declined)', added_text, re.IGNORECASE):
        patterns["adds_return_early"] = True

    # Code removal (net negative)
    if len(removed_lines) > len(added_lines):
        patterns["removes_code"] = True

    # Error handling
    if re.search(r'catch\s*\(|except|try\s*\{|error_msg|log_error|pr_err', added_text):
        patterns["adds_error_handling"] = True

    # Type changes
    if re.search(r'(uint16_t|int|long|size_t|unsigned)', removed_text) and \
       re.search(r'(uint16_t|int|long|size_t|unsigned)', added_text):
        patterns["changes_type"] = True

    # Input validation
    if re.search(r'valid|saniti|check|verify|assert', added_text):
        patterns["adds_validation"] = True

    # Backdoor removal
    if re.search(r'exec\(|system\(|runtime.*exec|backdoor|__backdoor', removed_text):
        patterns["removes_backdoor"] = True

    # Off-by-one
    if re.search(r'\+\s*1|\-\s*1|<=\s*len|<\s*len', added_text) and \
       re.search(r'<\s*len|<=\s*len', removed_text):
        patterns["fixes_off_by_one"] = True

    # Initialization
    if re.search(r'=\s*0;|=\s*null;|=\s*nullptr;|memset|bzero|calloc', added_text):
        patterns["adds_initialization"] = True

    # Loop bound changes
    if re.search(r'while|for\s*\(', added_text) or \
       (re.search(r'while|for\s*\(', removed_text) and added_text):
        patterns["changes_loop_bound"] = True

    # Sanitization
    if re.search(r'escape|encode|sanitiz|htmlspecialchar|urlencode|quote', added_text):
        patterns["adds_sanitization"] = True

    # Comparison changes
    if re.search(r'[<>=!]=', removed_text) and re.search(r'[<>=!]=', added_text):
        patterns["changes_comparison"] = True

    return patterns


def get_dominant_patterns(patterns: dict) -> list[str]:
    """Return the list of True boolean patterns from an extraction result."""
    return [k for k, v in patterns.items() if v is True]


def describe_patterns(patterns: dict) -> str:
    """Convert extracted patterns into a natural-language structural summary."""
    active = get_dominant_patterns(patterns)
    total_added = patterns.get("total_added", 0)
    total_removed = patterns.get("total_removed", 0)

    parts = [f"Lines added: {total_added}, lines removed: {total_removed}"]

    structural = []
    for p in active:
        if p in PATTERN_DESCRIPTIONS:
            structural.append(f"- {PATTERN_DESCRIPTIONS[p]}")

    if structural:
        parts.append("Structural patterns detected:\n" + "\n".join(structural))
    else:
        parts.append("No strong structural patterns detected.")

    return "\n".join(parts)
