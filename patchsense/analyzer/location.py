"""Patch location analysis — classify WHERE in the code a patch applies its fix.

The primary failure mode for false negatives in PatchSense is the LLM applying
"guard-without-root-fix" to patches that ARE canonical root-cause fixes for
their vulnerability family. This module provides heuristic evidence to counter
that misclassification.

Five canonical root-cause patterns detected:

  nullify-after-free    Sets freed pointer to NULL — canonical UAF/double-free fix.
                        Pattern: ptr = NULL after free(ptr) in same hunk.

  remove-dangerous-op   Removes the operation that causes the vulnerability.
                        Pattern: removal of free() or overflow arithmetic without replacement.

  return-value-fix      Changes what a function returns to prevent caller misuse.
                        Pattern: removed return X → added return Y in same hunk.

  operation-reorder     Moves operations to change their execution order.
                        Pattern: removed lines reappear as added lines in different position.

  guard-at-vuln-site    Bounds/null check added adjacent to the dangerous operation.
                        Pattern: added if-check within same hunk as dangerous write/read/use.

  unknown               No pattern matched — let the LLM decide from context.

Root cause: all of these patterns get misclassified as "guard-without-root-fix" by
the LLM because it sees defensive-looking code without recognizing that for the specific
vulnerability being fixed, that defensive pattern IS the root-cause fix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from patchsense.models import ParsedPatch


@dataclass
class PatchLocationContext:
    """Result of heuristic patch location analysis."""
    location_type: str  # see module docstring for valid values
    evidence: str       # human-readable explanation for injection into LLM prompt
    dangerous_ops_in_hunk: list[str] = field(default_factory=list)
    is_at_vulnerability_site: bool = False


# ---------------------------------------------------------------------------
# Free function variants (C, C++, Java-adjacent)
# ---------------------------------------------------------------------------
_FREE_RE = re.compile(
    r"\b(free|xmlFree|xmlFreeNode|ngx_free|ngx_pfree|kfree|g_free|"
    r"cfree|efree|apr_pool_destroy|vfree|zfree)\s*\("
)

# ---------------------------------------------------------------------------
# Dangerous operations whose presence near a guard means guard-at-vuln-site
# ---------------------------------------------------------------------------
_DANGEROUS_OPS_RE = re.compile(
    r"\b(memset|memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|"
    r"gets|scanf|malloc|calloc|realloc|alloca|free|xmlFree|ngx_free|kfree|"
    r"RETURN_ERROR_IF|ZSTD_|write|read|send|recv)\b"
)

# Array index access: var[expr]
_ARRAY_ACCESS_RE = re.compile(r"\w+\[[\w\s+\-*/<>]+\]")

# Null assignment: foo = NULL  or  foo->bar = NULL
_NULL_ASSIGN_RE = re.compile(
    r"([\w\->.\[\]]+)\s*=\s*(?:NULL|nullptr|nil|0)\s*;"
)

# Bounds-style if-conditions: if (i < n) or if (nOut + 4 > nAlloc) etc.
_BOUNDS_IF_RE = re.compile(
    r"\bif\b.{0,80}(?:[<>]=?|==|!=).{0,80}"
    r"(?:sizeof|nAlloc|capacity|size|len|count|limit|max|min|Cap|Len|Size|Buf)",
    re.IGNORECASE,
)

# Loop bound conditions: while (i < sizeof(x)/sizeof(x[0]))
_LOOP_BOUND_RE = re.compile(
    r"\b(while|for)\b.{0,80}\bi\s*<",
    re.IGNORECASE,
)

# RETURN_ERROR_IF style macros common in zstd/lz4
_ERROR_MACRO_RE = re.compile(r"\bRETURN_ERROR_IF\b|\bRETURN_ERROR\b|\bGOTO_ERROR\b")

# Arithmetic that can overflow: x += 1, x++, ++x
_OVERFLOW_ARITH_RE = re.compile(r"\b\w+\s*\+=\s*\d+\b|\+\+\w+|\b\w+\+\+")

# Pointer/buffer declarations in C — indicates buffer operation in scope
_POINTER_DECL_RE = re.compile(
    r"\b(?:BYTE|char|uint\d+_t|int8_t|uchar|u8|u16|u32|void)\s*\*"
    r"|\b\w+\s*\*\s*(?:const\s+)?\w+"
)
# Pointer write through indirection: *ptr = ..., or ptr[i] =
_POINTER_WRITE_RE = re.compile(r"\*\w+\s*=|\w+\s*\[\s*\w+[\s+\-*]*\]\s*=")


def analyze_patch_location(parsed_patch: ParsedPatch) -> PatchLocationContext:
    """Classify WHERE in the code the patch applies its fix.

    Checks five canonical root-cause patterns in priority order.
    Returns the first match, or 'unknown' if none match.

    This function is intentionally conservative: it only returns a positive
    result when the evidence is strong enough to override the LLM's default
    interpretation. When in doubt, it returns 'unknown'.
    """
    # Aggregate lines across all hunks
    all_added: list[str] = []
    all_removed: list[str] = []
    all_context: list[str] = []

    for hunk in parsed_patch.hunks:
        all_added.extend(hunk.added_lines)
        all_removed.extend(hunk.removed_lines)
        all_context.extend(hunk.context_before + hunk.context_after)

    # Check in priority order
    result = (
        _check_nullify_after_free(all_added, all_removed, all_context)
        or _check_remove_dangerous_op(all_added, all_removed)
        or _check_return_value_fix(all_added, all_removed)
        or _check_operation_reorder(all_added, all_removed, parsed_patch)
        or _check_guard_at_vuln_site(all_added, all_removed, all_context)
    )

    return result or PatchLocationContext(
        location_type="unknown",
        evidence="No specific location pattern detected — LLM should assess from code structure.",
        is_at_vulnerability_site=False,
    )


# ---------------------------------------------------------------------------
# Pattern detectors
# ---------------------------------------------------------------------------

def _check_nullify_after_free(
    added: list[str],
    removed: list[str],
    context: list[str],
) -> Optional[PatchLocationContext]:
    """Detect: pointer set to NULL after free() — canonical UAF/double-free fix.

    Matches when an added line assigns NULL to a variable that was free()'d
    in a removed, added, or context line within the same patch hunk.
    """
    # Collect all freed variable expressions from the entire hunk window
    all_lines = removed + added + context
    freed_vars: set[str] = set()
    for line in all_lines:
        for m in _FREE_RE.finditer(line):
            # Grab the argument to free(): everything between ( and first , or )
            rest = line[m.end():]
            arg_match = re.match(r"([^,);]+)", rest)
            if arg_match:
                arg = arg_match.group(1).strip()
                freed_vars.add(arg)
                # Also add base name (strips -> and [])
                freed_vars.add(re.split(r"[\->\.\[]", arg)[0].strip())

    if not freed_vars:
        return None

    # Check added lines for NULL assignment to a freed variable
    for line in added:
        m = _NULL_ASSIGN_RE.search(line)
        if not m:
            continue
        lhs = m.group(1).strip()
        lhs_base = re.split(r"[\->\.\[]", lhs)[0].strip()
        if lhs in freed_vars or lhs_base in freed_vars:
            return PatchLocationContext(
                location_type="nullify-after-free",
                evidence=(
                    f"Sets '{lhs}' to NULL after free — "
                    f"canonical root-cause fix for use-after-free and double-free vulnerabilities. "
                    f"Eliminates the dangling pointer that enables the exploit."
                ),
                is_at_vulnerability_site=True,
            )

    return None


def _check_remove_dangerous_op(
    added: list[str],
    removed: list[str],
) -> Optional[PatchLocationContext]:
    """Detect: removal of the operation that causes the vulnerability.

    Case A — removes a free() call without replacing it with another free.
    Case B — removes overflow-causing arithmetic without replacing it.
    """
    # Case A: removed a free() call
    removed_frees = [l for l in removed if _FREE_RE.search(l)]
    if removed_frees:
        added_frees = [l for l in added if _FREE_RE.search(l)]
        # Only if the free is truly removed (not replaced by a different free)
        if len(added_frees) < len(removed_frees):
            example = removed_frees[0].strip()[:80]
            return PatchLocationContext(
                location_type="remove-dangerous-op",
                evidence=(
                    f"Removes premature free() call: {example!r}. "
                    f"Eliminates the root cause of the use-after-free — "
                    f"the object is no longer deallocated at this point."
                ),
                is_at_vulnerability_site=True,
            )

    # Case B: removes overflow-causing arithmetic (e.g., `arg += 1`)
    removed_arith = [l for l in removed if _OVERFLOW_ARITH_RE.search(l)]
    if removed_arith:
        added_arith = [l for l in added if _OVERFLOW_ARITH_RE.search(l)]
        if not added_arith:
            # No replacement arithmetic added — arithmetic was removed
            example = removed_arith[0].strip()[:80]
            return PatchLocationContext(
                location_type="remove-dangerous-op",
                evidence=(
                    f"Removes overflow-prone arithmetic: {example!r}. "
                    f"Eliminates the signed integer overflow at its source."
                ),
                is_at_vulnerability_site=True,
            )

    return None


def _check_return_value_fix(
    added: list[str],
    removed: list[str],
) -> Optional[PatchLocationContext]:
    """Detect: changes what a function returns, preventing the caller from misusing a freed resource.

    Matches when both removed and added lines have return statements with different values.
    """
    _ret_val_re = re.compile(r"\breturn\s+(\S+?)\s*;")

    old_vals = [m.group(1) for l in removed for m in [_ret_val_re.search(l)] if m]
    new_vals = [m.group(1) for l in added for m in [_ret_val_re.search(l)] if m]

    if old_vals and new_vals and old_vals[0] != new_vals[0]:
        return PatchLocationContext(
            location_type="return-value-fix",
            evidence=(
                f"Changes return value from {old_vals[0]!r} to {new_vals[0]!r}. "
                f"Fixes the root cause by preventing the caller from treating a "
                f"closed/freed resource as still valid — the error code change "
                f"breaks the control flow that leads to the dangerous dereference."
            ),
            is_at_vulnerability_site=True,
        )

    return None


def _check_operation_reorder(
    added: list[str],
    removed: list[str],
    parsed_patch: ParsedPatch,
) -> Optional[PatchLocationContext]:
    """Detect: reordering of operations to change execution order.

    Matches when the same non-trivial code appears in both removed and added
    lines (same content, different position in the file). Typical example:
    decode-after-normalize (wrong) → decode-before-normalize (correct).

    We require at least one reordered line to be a meaningful statement
    (contains a function call or assignment, not just a blank/comment).
    """
    # Only reliable for single-hunk patches
    if len(parsed_patch.hunks) != 1:
        return None

    removed_stripped = {l.strip() for l in removed if _is_meaningful(l)}
    added_stripped = {l.strip() for l in added if _is_meaningful(l)}

    overlap = removed_stripped & added_stripped
    if not overlap:
        return None

    # Overlap ratio: most of the changed lines appear in both (it's a move, not a replacement)
    total = max(len(removed_stripped), len(added_stripped), 1)
    if len(overlap) / total < 0.4:
        return None

    # Confirm the lines actually moved (different position) by checking full removed vs added
    # Heuristic: if removed and added are different sequences with same elements, it's a reorder
    removed_list = [l.strip() for l in removed if l.strip() in overlap]
    added_list = [l.strip() for l in added if l.strip() in overlap]

    if len(overlap) > 1 and removed_list == added_list:
        # Multiple overlapping lines in same order — not a reorder, likely duplication
        return None

    # Detect "wrap in guard" pattern: the overlapping operation was surrounded by
    # a new control structure (if, try, catch, while). This is a guard addition,
    # NOT a reorder. Example: free(x) → if (cond) { free(x); } or
    # exec(cmd) → try { exec(cmd); } catch { ... }
    # (All three of the operation-reorder false positives are this pattern.)
    added_structural = any(
        re.match(r"\s*(?:if|try|catch|while|for|switch)\s*[\(\{]", l)
        for l in added
    )
    if added_structural:
        # The overlapping content was wrapped in a control structure — not a true reorder
        return None

    examples = list(overlap)[:1]
    return PatchLocationContext(
        location_type="operation-reorder",
        evidence=(
            f"Reorders operations (moved: {examples[0][:60]!r}) — "
            f"changes execution sequence to prevent the vulnerability from being exploitable. "
            f"This is a structural root-cause fix, not a defensive guard."
        ),
        is_at_vulnerability_site=True,
    )


def _check_guard_at_vuln_site(
    added: list[str],
    removed: list[str],
    context: list[str],
) -> Optional[PatchLocationContext]:
    """Detect: bounds/error check added immediately adjacent to the dangerous operation.

    A guard is 'at the vulnerability site' when the check and the dangerous
    operation appear in the same hunk — the check is placed directly before the
    write, read, or use that it is protecting.

    Contrast with 'guard at call site': the check is in a CALLER function and the
    dangerous operation is downstream in a callee. That pattern might still be
    suppression. But when both the check AND the dangerous operation are in the
    same hunk (same function, same scope), the check IS at the vulnerability site.
    """
    # Find bounds-style guards in added lines
    guards_added: list[str] = []
    for line in added:
        if (
            _BOUNDS_IF_RE.search(line)
            or _LOOP_BOUND_RE.search(line)
            or _ERROR_MACRO_RE.search(line)
        ):
            guards_added.append(line.strip()[:80])

    if not guards_added:
        return None

    # Find dangerous operations in the hunk context (removed + context lines)
    dangerous_ops: list[str] = []
    search_lines = removed + context
    for line in search_lines:
        m = _DANGEROUS_OPS_RE.search(line)
        if m:
            dangerous_ops.append(m.group(1))
        if _ARRAY_ACCESS_RE.search(line):
            dangerous_ops.append("array-write/read")
        if _POINTER_WRITE_RE.search(line):
            dangerous_ops.append("pointer-write")
        if _POINTER_DECL_RE.search(line):
            dangerous_ops.append("buffer-pointer")

    # Also: if an error-return macro guards a function whose context is all
    # pointer/buffer setup (e.g., zstd RETURN_ERROR_IF at function entry),
    # treat the macro itself as evidence of guarding a write operation below it.
    if not dangerous_ops and guards_added:
        if any(_ERROR_MACRO_RE.search(g) for g in guards_added):
            # Check if context suggests buffer/pointer work
            context_text = " ".join(context + removed)
            if _POINTER_DECL_RE.search(context_text) or "dst" in context_text or "buf" in context_text:
                dangerous_ops.append("buffer-write-in-function")

    if not dangerous_ops:
        return None

    unique_ops = list(dict.fromkeys(dangerous_ops))[:3]
    return PatchLocationContext(
        location_type="guard-at-vulnerability-site",
        evidence=(
            f"Bounds check ({guards_added[0]!r}) added in the same scope as "
            f"dangerous operation(s): {', '.join(unique_ops)}. "
            f"The guard is AT the vulnerability site — "
            f"this is the canonical fix for this family, not upstream call-site suppression."
        ),
        dangerous_ops_in_hunk=unique_ops,
        is_at_vulnerability_site=True,
    )


def _is_meaningful(line: str) -> bool:
    """Return True if a diff line is a non-trivial code statement."""
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return False
    if stripped in ("{", "}", "};"):
        return False
    return len(stripped) > 8


def format_location_for_prompt(ctx: PatchLocationContext) -> str:
    """Format location context as text for injection into the alignment prompt.

    Two tiers of guidance:
    - Tier 1 (high precision — assertive): remove-dangerous-op, return-value-fix
    - Tier 2 (medium precision — advisory): nullify-after-free, guard-at-vulnerability-site

    For Tier 2 patterns, the LLM is told to verify from context rather than
    accepting the detection as definitive. This prevents over-correction on
    cases where the same pattern can indicate either a fix or a suppression.
    """
    if ctx.location_type == "unknown":
        return (
            "Location analysis: No canonical pattern matched. "
            "Assess from vulnerability description and patch structure."
        )

    type_labels = {
        "nullify-after-free": "NULLIFY-AFTER-FREE",
        "remove-dangerous-op": "REMOVE-DANGEROUS-OP",
        "return-value-fix": "RETURN-VALUE-FIX",
        "operation-reorder": "OPERATION-REORDER",
        "guard-at-vulnerability-site": "GUARD-AT-VULNERABILITY-SITE",
    }
    label = type_labels.get(ctx.location_type, ctx.location_type.upper())

    lines = [
        f"Detected pattern: {label}",
        f"Evidence: {ctx.evidence}",
    ]
    if ctx.dangerous_ops_in_hunk:
        lines.append(f"Co-located dangerous ops: {', '.join(ctx.dangerous_ops_in_hunk)}")
    lines.append("")

    # Tier 1: assertive — these patterns have near-100% precision as root-cause fixes
    if ctx.location_type == "remove-dangerous-op":
        lines.append(
            "CLASSIFICATION GUIDANCE (HIGH CONFIDENCE): Removing the operation "
            "that causes the vulnerability is a root-cause fix. "
            "Do NOT flag as guard-without-root-fix or symptom-suppression."
        )
    elif ctx.location_type == "return-value-fix":
        lines.append(
            "CLASSIFICATION GUIDANCE (HIGH CONFIDENCE): Changing the return value "
            "to prevent the caller from misusing a closed/freed resource "
            "is a root-cause fix. The change breaks the control flow that leads to "
            "the dangerous dereference. Do NOT flag as guard-without-root-fix."
        )
    elif ctx.location_type == "operation-reorder":
        lines.append(
            "CLASSIFICATION GUIDANCE (HIGH CONFIDENCE): Reordering operations to "
            "prevent exploit (e.g., decode before normalize rather than after) "
            "is a structural root-cause fix. Do NOT flag as guard-without-root-fix."
        )
    # Tier 2: advisory — verify from context before accepting as a root-cause fix
    elif ctx.location_type == "nullify-after-free":
        lines.extend([
            "CLASSIFICATION GUIDANCE (VERIFY FROM CONTEXT):",
            "  ROOT-CAUSE FIX if: the free() call is correct and intentional at",
            "    this location, and the only defect was the missing null assignment",
            "    (the dangling pointer would later be used without a NULL check).",
            "  SYMPTOM SUPPRESSION if: the free() itself is premature or incorrect",
            "    here, and nullifying doesn't remove that incorrect deallocation",
            "    — another code path can still trigger the UAF via the premature free.",
        ])
    elif ctx.location_type == "guard-at-vulnerability-site":
        lines.extend([
            "CLASSIFICATION GUIDANCE (VERIFY FROM CONTEXT):",
            "  ROOT-CAUSE FIX if: the check directly prevents the dangerous",
            "    write/read/use from proceeding (guard before the dangerous op).",
            "  SYMPTOM SUPPRESSION if: the check clamps an input variable to fit",
            "    an UNCHANGED allocation ('allocation-unchanged' pattern) — the",
            "    root cause (wrong allocation size or wrong copy length) remains.",
        ])

    return "\n".join(lines)
