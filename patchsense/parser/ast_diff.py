"""AST-level diff extraction using tree-sitter.

Identifies which named entities (functions, methods, structs) were modified,
giving the LLM analyzers richer structural context beyond raw line diffs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ChangedEntity:
    """A named code entity (function, method, struct) touched by the patch."""
    kind: str          # "function", "method", "struct", "class", etc.
    name: str
    file_path: str
    lines_removed: list[str] = field(default_factory=list)
    lines_added: list[str] = field(default_factory=list)


@dataclass
class ASTDiff:
    """Structural summary of what named entities a patch modifies."""
    changed_entities: list[ChangedEntity]
    language: str = "unknown"

    @property
    def function_names(self) -> list[str]:
        return [e.name for e in self.changed_entities if e.kind in ("function", "method")]


def extract_ast_diff(parsed_patch, original_source: Optional[str] = None) -> ASTDiff:
    """
    Extract structural (AST-level) context from a ParsedPatch.

    Attempts tree-sitter parsing; falls back to heuristic regex extraction
    if tree-sitter language bindings are unavailable.
    """
    language = _detect_language(parsed_patch.files_changed)

    try:
        return _extract_with_treesitter(parsed_patch, original_source, language)
    except Exception:
        return _extract_with_heuristics(parsed_patch, language)


# ---------------------------------------------------------------------------
# tree-sitter path
# ---------------------------------------------------------------------------

def _extract_with_treesitter(parsed_patch, source: Optional[str], language: str) -> ASTDiff:
    """Use tree-sitter to find which function/method each hunk falls inside."""
    import tree_sitter_c
    import tree_sitter_java
    from tree_sitter import Language, Parser

    lang_map = {
        "c": tree_sitter_c.language(),
        "java": tree_sitter_java.language(),
    }

    if language not in lang_map:
        raise ValueError(f"No tree-sitter binding for language: {language}")

    ts_lang = Language(lang_map[language])
    parser = Parser(ts_lang)

    if not source:
        raise ValueError("original_source required for tree-sitter extraction")

    tree = parser.parse(source.encode())
    func_ranges = _collect_function_ranges(tree.root_node, language)

    entities: list[ChangedEntity] = []
    seen: set[str] = set()

    for hunk in parsed_patch.hunks:
        line = hunk.start_line_original
        for (name, start, end) in func_ranges:
            if start <= line <= end and name not in seen:
                seen.add(name)
                kind = "method" if language == "java" else "function"
                entities.append(ChangedEntity(
                    kind=kind,
                    name=name,
                    file_path=hunk.file_path,
                    lines_removed=hunk.removed_lines,
                    lines_added=hunk.added_lines,
                ))

    return ASTDiff(changed_entities=entities, language=language)


def _collect_function_ranges(node, language: str) -> list[tuple[str, int, int]]:
    """Walk a tree-sitter AST and collect (name, start_line, end_line) for functions."""
    results: list[tuple[str, int, int]] = []
    target_types = {
        "c": {"function_definition"},
        "java": {"method_declaration", "constructor_declaration"},
    }.get(language, {"function_definition"})

    def walk(n):
        if n.type in target_types:
            name = _find_identifier(n)
            if name:
                results.append((name, n.start_point[0] + 1, n.end_point[0] + 1))
        for child in n.children:
            walk(child)

    walk(node)
    return results


def _find_identifier(node) -> Optional[str]:
    """Find the first identifier child of a function/method node."""
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode()
        if child.type == "function_declarator":
            return _find_identifier(child)
    return None


# ---------------------------------------------------------------------------
# Heuristic fallback (regex-based)
# ---------------------------------------------------------------------------

_C_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "return",
    "break", "continue", "goto", "typedef", "struct", "union", "enum",
    "sizeof", "void", "int", "char", "long", "short", "unsigned", "signed",
    "static", "extern", "const", "volatile", "inline", "register",
})
_C_FUNC_RE = re.compile(
    r"^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{",
    re.MULTILINE,
)
_JAVA_METHOD_RE = re.compile(
    r"(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{",
    re.MULTILINE,
)


def _extract_with_heuristics(parsed_patch, language: str) -> ASTDiff:
    """Regex-based fallback to infer modified function names from diff context."""
    pattern = _JAVA_METHOD_RE if language == "java" else _C_FUNC_RE
    entities: list[ChangedEntity] = []
    seen: set[str] = set()

    for hunk in parsed_patch.hunks:
        context = "\n".join(hunk.context_before + hunk.removed_lines + hunk.added_lines)
        for m in pattern.finditer(context):
            name = m.group(1)
            if name and name not in seen and name not in _C_KEYWORDS:
                seen.add(name)
                kind = "method" if language == "java" else "function"
                entities.append(ChangedEntity(
                    kind=kind,
                    name=name,
                    file_path=hunk.file_path,
                    lines_removed=hunk.removed_lines,
                    lines_added=hunk.added_lines,
                ))

    return ASTDiff(changed_entities=entities, language=language)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXT_LANG = {
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c",
    ".java": "java",
}


def _detect_language(files: list[str]) -> str:
    for f in files:
        ext = Path(f).suffix.lower()
        if ext in _EXT_LANG:
            return _EXT_LANG[ext]
    return "c"  # default to C (most AIxCC challenge projects are C)
