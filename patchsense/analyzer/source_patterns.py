"""Source code vulnerability pattern detection.

Inverts the 15 diff-based structural patterns into source-code vulnerability
indicators. Where diff patterns detect "adds_validation", source patterns
detect "missing_validation_before_dangerous_op".

These are heuristic candidates — the LLM confirmation step in detect.py
filters false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SourceVulnIndicator:
    """A potential vulnerability indicator found in source code."""
    pattern: str          # e.g., "missing_input_validation"
    line_number: int      # approximate line where the issue is
    context: str          # the relevant code snippet (1-3 lines)
    severity: str = "medium"  # "low", "medium", "high"
    description: str = ""


@dataclass
class SourceAnalysisResult:
    """Complete result of source code pattern analysis."""
    file_path: str = ""
    language: str = ""
    indicators: list[SourceVulnIndicator] = field(default_factory=list)
    functions_analyzed: int = 0
    lines_analyzed: int = 0

    @property
    def has_candidates(self) -> bool:
        """True if ≥2 indicators co-occur (our noise filter threshold)."""
        return len(self.indicators) >= 2

    def indicators_by_function(self) -> dict[str, list[SourceVulnIndicator]]:
        """Group indicators by the function they appear in."""
        # Approximate: group by proximity (within 20 lines)
        groups: dict[str, list[SourceVulnIndicator]] = {}
        for ind in sorted(self.indicators, key=lambda x: x.line_number):
            placed = False
            for key, group in groups.items():
                if abs(ind.line_number - group[-1].line_number) < 30:
                    group.append(ind)
                    placed = True
                    break
            if not placed:
                groups[f"region_{ind.line_number}"] = [ind]
        return groups


def detect_language(source: str, file_path: str = "") -> str:
    """Detect source language from file extension or content heuristics."""
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

    if ext in ("c", "h"):
        return "c"
    if ext in ("cpp", "cc", "cxx", "hpp", "hxx"):
        return "cpp"
    if ext == "java":
        return "java"
    if ext in ("py", "pyw"):
        return "python"

    # Content heuristics
    if re.search(r'#include\s*[<"]', source):
        return "c"
    if re.search(r'(public|private|protected)\s+(class|interface|enum)', source):
        return "java"
    if re.search(r'def\s+\w+\s*\(|import\s+\w+', source):
        return "python"

    return "unknown"


# ============================================================================
# C/C++ source patterns
# ============================================================================

def _analyze_c_source(source: str) -> list[SourceVulnIndicator]:
    """Detect vulnerability patterns in C/C++ source code."""
    indicators = []
    lines = source.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Skip comments and preprocessor
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("#"):
            continue

        # --- missing_length_check: memcpy/strcpy/sprintf without length check ---
        copy_match = re.search(r'\b(memcpy|strcpy|strcat|sprintf|gets)\s*\(', stripped)
        if copy_match:
            # Check if there's a length check within ±5 lines that is relevant
            # to the copy operation (not an unrelated sizeof in e.g. malloc)
            context_window = "\n".join(lines[max(0, i - 6):i + 5]).lower()
            func_name = copy_match.group(1)
            # Look for strlen, .size(), .length, or a comparison check
            has_length_check = bool(re.search(r'strlen|\.size\(\)|\.length|if\s*\(.+[<>]', context_window))
            # sizeof is only relevant if it refers to the destination buffer,
            # not an unrelated allocation like malloc(sizeof(int))
            if not has_length_check and re.search(r'sizeof', context_window):
                # sizeof in the same line as the copy, or sizeof of a buffer
                # variable (not sizeof(type) in a malloc) counts as a check
                copy_line_lower = stripped.lower()
                if 'sizeof' in copy_line_lower:
                    has_length_check = True
                else:
                    # Check for sizeof(buf_name) pattern, not sizeof(type)
                    for ctx_line in lines[max(0, i - 6):i + 5]:
                        ctx_lower = ctx_line.strip().lower()
                        if 'sizeof' in ctx_lower and 'malloc' not in ctx_lower and 'calloc' not in ctx_lower:
                            has_length_check = True
                            break
            if not has_length_check:
                indicators.append(SourceVulnIndicator(
                    pattern="missing_length_check",
                    line_number=i,
                    context=stripped[:120],
                    severity="high",
                    description=f"Unsafe copy/format function without length validation",
                ))

        # --- fixed_buffer_with_variable_input: char buf[N] near unbounded copy ---
        if re.search(r'\bchar\s+\w+\s*\[\s*\d+\s*\]', stripped):
            # Look for copy operations within ±10 lines
            context_window = "\n".join(lines[i - 1:min(len(lines), i + 10)])
            if re.search(r'(memcpy|strcpy|strcat|sprintf|scanf|fgets|read)\s*\(', context_window):
                length_context = "\n".join(lines[max(0, i - 1):min(len(lines), i + 10)]).lower()
                if not re.search(r'sizeof\s*\(|strlen|min\s*\(|\.size\(\)', length_context):
                    indicators.append(SourceVulnIndicator(
                        pattern="fixed_buffer_with_variable_input",
                        line_number=i,
                        context=stripped[:120],
                        severity="high",
                        description="Fixed-size buffer near copy operation without size validation",
                    ))

        # --- unchecked_null_deref: pointer from function call without null check ---
        # Covers allocators (malloc/calloc/realloc) AND any function returning
        # a pointer that is subsequently dereferenced without a null check.
        # This is the general pattern behind CWE-476 — not just allocators.
        alloc_match = re.search(r'\b(malloc|calloc|realloc)\s*\(', stripped)
        if alloc_match:
            # Check if result is null-checked within ±3 lines
            context_after = "\n".join(lines[i - 1:min(len(lines), i + 3)]).lower()
            if not re.search(r'if\s*\(.+==\s*null|if\s*\(\s*!\s*\w+\s*\)', context_after):
                indicators.append(SourceVulnIndicator(
                    pattern="unchecked_null_deref",
                    line_number=i,
                    context=stripped[:120],
                    severity="medium",
                    description="Allocation result not checked for NULL",
                ))

        # General case: pointer assigned from function call, then dereferenced
        # Pattern: type *var = func(...); ... var->field (without null check)
        ptr_assign = re.search(
            r'(?:struct\s+\w+|[\w_]+)\s*\*\s*(\w+)\s*=\s*(\w+)\s*\(',
            stripped,
        )
        if ptr_assign and not alloc_match:
            ptr_name = ptr_assign.group(1)
            func_name = ptr_assign.group(2)
            # Check if dereferenced via -> within ±5 lines without a null check
            context_after = "\n".join(lines[i:min(len(lines), i + 5)])
            if re.search(rf'\b{re.escape(ptr_name)}\s*->', context_after):
                # Check if null-checked before dereference
                context_check = "\n".join(lines[i - 1:min(len(lines), i + 5)]).lower()
                if not re.search(
                    rf'if\s*\(\s*!?\s*{re.escape(ptr_name.lower())}|'
                    rf'if\s*\(.+{re.escape(ptr_name.lower())}\s*==\s*null|'
                    rf'if\s*\(.+{re.escape(ptr_name.lower())}\s*!=\s*null',
                    context_check,
                ):
                    indicators.append(SourceVulnIndicator(
                        pattern="unchecked_null_deref",
                        line_number=i,
                        context=stripped[:120],
                        severity="high",
                        description=f"Pointer '{ptr_name}' from {func_name}() "
                                    f"dereferenced without NULL check",
                    ))

        # --- uninitialized_use: variable declared without initializer ---
        if re.search(r'^\s*(int|char|long|size_t|unsigned|float|double|void\s*\*)\s+\w+\s*;', stripped):
            var_match = re.search(r'(int|char|long|size_t|unsigned|float|double)\s+(\w+)\s*;', stripped)
            if var_match:
                var_name = var_match.group(2)
                # Check if initialized within ±10 lines (C89 style: declare at
                # top, initialize later — 3 lines was too narrow and caused
                # massive false positives on well-written C code like SQLite)
                context_after = "\n".join(lines[i - 1:min(len(lines), i + 10)])
                is_initialized = bool(re.search(
                    rf'{re.escape(var_name)}\s*=|'         # direct assignment
                    rf'&{re.escape(var_name)}\b|'          # passed as output param
                    rf'{re.escape(var_name)}\s*\[',        # used as array (implies init)
                    context_after,
                ))
                if not is_initialized:
                    indicators.append(SourceVulnIndicator(
                        pattern="uninitialized_use",
                        line_number=i,
                        context=stripped[:120],
                        severity="medium",
                        description=f"Variable '{var_name}' declared without initialization",
                    ))

        # --- missing_error_handling: system calls without return check ---
        if re.search(r'\b(open|read|write|fopen|fread|socket|connect|bind)\s*\(', stripped):
            if not re.search(r'if\s*\(|=\s*-?\d+|==|!=', stripped):
                context_after = "\n".join(lines[i - 1:min(len(lines), i + 2)]).lower()
                if not re.search(r'if\s*\(.+[<>=!]', context_after):
                    indicators.append(SourceVulnIndicator(
                        pattern="missing_error_handling",
                        line_number=i,
                        context=stripped[:120],
                        severity="medium",
                        description="System call return value not checked",
                    ))

        # --- dangerous_type_narrowing: cast from larger to smaller type ---
        if re.search(r'\(\s*(char|short|uint8_t|int8_t|uint16_t|int16_t)\s*\)', stripped):
            # Check if the source value could be larger
            if re.search(r'(size_t|long|int|uint32_t|uint64_t|ssize_t)', stripped):
                indicators.append(SourceVulnIndicator(
                    pattern="dangerous_type_narrowing",
                    line_number=i,
                    context=stripped[:120],
                    severity="medium",
                    description="Type narrowing cast may cause truncation",
                ))

        # --- unchecked_array_access: array index without bounds check ---
        array_match = re.search(r'(\w+)\s*\[\s*(\w+)\s*\]', stripped)
        if array_match and not stripped.startswith("for"):
            idx_var = array_match.group(2)
            arr_name = array_match.group(1)
            # Skip constant indices and common safe patterns
            if not idx_var.isdigit():
                # Wider window (±10 lines) to catch bounds checks in mature code
                context_window = "\n".join(lines[max(0, i - 10):i + 1]).lower()
                idx_lower = re.escape(idx_var.lower())
                arr_lower = re.escape(arr_name.lower())

                # Check for any of these protective patterns:
                has_bounds_check = bool(re.search(
                    rf'if\s*\(.+{idx_lower}\s*[<>]|'    # if(idx < limit)
                    rf'if\s*\(.+[<>]\s*{idx_lower}|'    # if(limit > idx)
                    rf'for\s*\(.+{idx_lower}|'           # for loop bounds
                    rf'while\s*\(.+{idx_lower}|'         # while loop bounds
                    rf'assert\s*\(.+{idx_lower}|'        # assert(idx < N)
                    rf'{idx_lower}\s*%\s*\d|'            # idx % N (modular)
                    rf'{idx_lower}\s*&\s*\d|'            # idx & mask (bitwise)
                    rf'min\s*\(.+{idx_lower}|'           # MIN(idx, limit)
                    rf'{idx_lower}\s*=\s*.*%|'           # idx = ... % N
                    rf'switch\s*\(\s*{idx_lower}',       # switch(idx)
                    context_window,
                ))
                if not has_bounds_check:
                    indicators.append(SourceVulnIndicator(
                        pattern="unchecked_array_access",
                        line_number=i,
                        context=stripped[:120],
                        severity="medium",
                        description=f"Array index '{idx_var}' not validated against bounds",
                    ))

        # --- use_after_free: free() followed by use of same pointer ---
        free_match = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', stripped)
        if free_match:
            freed_var = free_match.group(1)
            # Check if the pointer is used (not nullified) in ±5 lines after
            context_after = "\n".join(lines[i:min(len(lines), i + 5)])
            if re.search(rf'\b{re.escape(freed_var)}\b', context_after):
                if not re.search(rf'{re.escape(freed_var)}\s*=\s*(NULL|nullptr|0)', context_after):
                    indicators.append(SourceVulnIndicator(
                        pattern="use_after_free",
                        line_number=i,
                        context=stripped[:120],
                        severity="high",
                        description=f"Pointer '{freed_var}' used after free without nullification",
                    ))

    return indicators


# ============================================================================
# Java source patterns
# ============================================================================

def _analyze_java_source(source: str) -> list[SourceVulnIndicator]:
    """Detect vulnerability patterns in Java source code."""
    indicators = []
    lines = source.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # --- missing_sanitization: string concat in SQL/HTML/command ---
        if re.search(r'(executeQuery|executeUpdate|execute)\s*\(', stripped):
            # Check if the query argument or nearby lines use string concat
            # (the concatenation may be on a preceding line that builds the query)
            context_window = "\n".join(lines[max(0, i - 6):i + 1])
            if re.search(r'"\s*\+\s*\w+|String\.format', context_window):
                # Also check it's not using PreparedStatement
                if not re.search(r'PreparedStatement|prepareStatement|\?', context_window):
                    indicators.append(SourceVulnIndicator(
                        pattern="missing_sanitization",
                        line_number=i,
                        context=stripped[:120],
                        severity="high",
                        description="SQL query built with string concatenation (injection risk)",
                    ))
            # Also flag direct string concat on the same execute line
            elif re.search(r'"\s*\+\s*\w+|String\.format', stripped):
                indicators.append(SourceVulnIndicator(
                    pattern="missing_sanitization",
                    line_number=i,
                    context=stripped[:120],
                    severity="high",
                    description="SQL query built with string concatenation (injection risk)",
                ))

        # --- missing_sanitization: HTML output without encoding ---
        if re.search(r'(getWriter|println|print|write)\s*\(', stripped):
            if re.search(r'getParameter|getHeader|getCookie|getQueryString', stripped):
                indicators.append(SourceVulnIndicator(
                    pattern="missing_sanitization",
                    line_number=i,
                    context=stripped[:120],
                    severity="high",
                    description="User input written to output without sanitization (XSS risk)",
                ))

        # --- missing_input_validation: user input used directly ---
        if re.search(r'(getParameter|getHeader|readLine|nextLine)\s*\(', stripped):
            context_after = "\n".join(lines[i - 1:min(len(lines), i + 5)]).lower()
            if not re.search(r'valid|check|sanitiz|pattern|matcher|regex|parse|trim', context_after):
                indicators.append(SourceVulnIndicator(
                    pattern="missing_input_validation",
                    line_number=i,
                    context=stripped[:120],
                    severity="medium",
                    description="User input used without validation",
                ))

        # --- missing_error_handling: risky operation without try/catch ---
        if re.search(r'\.(parse|valueOf|decode|read|connect|open)\s*\(', stripped):
            context_window = "\n".join(lines[max(0, i - 3):min(len(lines), i + 3)]).lower()
            if not re.search(r'try\s*\{|catch\s*\(', context_window):
                indicators.append(SourceVulnIndicator(
                    pattern="missing_error_handling",
                    line_number=i,
                    context=stripped[:120],
                    severity="low",
                    description="Fallible operation without try/catch",
                ))

        # --- path_traversal: file path from user input ---
        if re.search(r'new\s+File\s*\(|Paths\.get\s*\(|Path\.of\s*\(', stripped):
            if re.search(r'getParameter|request\.|input|param|arg', stripped):
                context_window = "\n".join(lines[max(0, i - 3):min(len(lines), i + 3)]).lower()
                if not re.search(r'canonical|normalize|resolve|startswith|contains\s*\(\s*"\.\."', context_window):
                    indicators.append(SourceVulnIndicator(
                        pattern="path_traversal",
                        line_number=i,
                        context=stripped[:120],
                        severity="high",
                        description="File path constructed from user input without canonicalization",
                    ))

        # --- command_injection: Runtime.exec or ProcessBuilder with user input ---
        if re.search(r'Runtime.*exec\s*\(|ProcessBuilder|exec\s*\(', stripped):
            if re.search(r'getParameter|request\.|input|param|arg|\+\s*\w+', stripped):
                indicators.append(SourceVulnIndicator(
                    pattern="command_injection",
                    line_number=i,
                    context=stripped[:120],
                    severity="high",
                    description="Command execution with user-controlled input",
                ))

    return indicators


# ============================================================================
# Public API
# ============================================================================

def extract_source_patterns(
    source: str,
    file_path: str = "",
    language: str | None = None,
) -> SourceAnalysisResult:
    """Analyze source code for vulnerability patterns.

    Returns a SourceAnalysisResult with indicators for potential vulnerabilities.
    Use result.has_candidates (≥2 co-occurring indicators) to filter noise.

    Args:
        source: Source code text.
        file_path: Path to source file (for language detection).
        language: Override language detection ("c", "java", etc.).
    """
    lang = language or detect_language(source, file_path)
    lines = source.split("\n")

    if lang in ("c", "cpp"):
        indicators = _analyze_c_source(source)
    elif lang == "java":
        indicators = _analyze_java_source(source)
    else:
        indicators = []

    return SourceAnalysisResult(
        file_path=file_path,
        language=lang,
        indicators=indicators,
        functions_analyzed=0,  # TODO: count via tree-sitter
        lines_analyzed=len(lines),
    )
