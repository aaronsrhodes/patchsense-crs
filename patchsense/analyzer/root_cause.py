"""Component 1: Root Cause Extractor.

Uses the LLM to classify what structural change a patch makes and
describe what program behavior it alters — without yet judging
whether that change addresses the vulnerability's root cause.
"""

from __future__ import annotations

import json
import re

from patchsense.backends.base import LLMBackend
from patchsense.models import ParsedPatch, PatchCategory, RootCauseAnalysis
from patchsense.parser.ast_diff import ASTDiff
from patchsense.parser.diff import format_patch_for_llm


_SYSTEM_PROMPT = """\
You are a security-focused code reviewer specializing in vulnerability patch analysis.
Your task is to analyze a code patch and describe ONLY what structural change it makes,
without judging whether the change is correct or complete. Be precise and technical.
"""

_CATEGORIES = {c.value: c for c in PatchCategory}

_EXTRACTION_PROMPT = """\
Analyze this code patch and classify the structural change it makes.

Patch:
{patch_text}

{ast_context}

Vulnerability context: {vuln_desc}
CWE: {cwe}

Respond with a JSON object (no markdown, no code fences) with exactly these fields:
{{
  "patch_category": one of {categories},
  "changed_behavior": "One sentence: what program behavior does this patch change?",
  "category_confidence": float between 0.0 and 1.0,
  "structural_description": "2-3 sentences describing the structural change at a code level",
  "functions_modified": ["list", "of", "function", "names", "or", "empty"],
  "is_defensive_coding": true or false (does this add a guard/check rather than fix the underlying logic?)
}}
"""


def extract_root_cause(
    patch: ParsedPatch,
    ast_diff: ASTDiff,
    vuln_description: str,
    cwe: str = "",
    backend: LLMBackend | None = None,
) -> RootCauseAnalysis:
    """Run Component 1: classify patch structure and describe behavioral change."""
    if backend is None:
        from patchsense.backends.factory import default_backend
        backend = default_backend()

    patch_text = format_patch_for_llm(patch)
    ast_context = _format_ast_context(ast_diff)
    categories = [c.value for c in PatchCategory]

    prompt = _EXTRACTION_PROMPT.format(
        patch_text=patch_text,
        ast_context=ast_context,
        vuln_desc=vuln_description or "not provided — classify from code structure alone",
        cwe=cwe or "unspecified",
        categories=json.dumps(categories),
    )

    raw = backend.complete(_SYSTEM_PROMPT, prompt, max_tokens=1024)
    data = _parse_json_response(raw)

    # Merge LLM-detected function names with AST-detected ones
    llm_funcs = data.get("functions_modified") or []
    ast_funcs = ast_diff.function_names
    all_funcs = list(dict.fromkeys(llm_funcs + ast_funcs))  # deduplicate, preserve order

    category_str = data.get("patch_category", "other")
    category = _CATEGORIES.get(category_str, PatchCategory.OTHER)

    return RootCauseAnalysis(
        patch_category=category,
        changed_behavior=data.get("changed_behavior", ""),
        category_confidence=float(data.get("category_confidence", 0.5)),
        structural_description=data.get("structural_description", ""),
        functions_modified=all_funcs,
        is_defensive_coding=bool(data.get("is_defensive_coding", False)),
    )


def _format_ast_context(ast_diff: ASTDiff) -> str:
    if not ast_diff.changed_entities:
        return ""
    names = ", ".join(e.name for e in ast_diff.changed_entities[:10])
    return f"AST analysis — modified {ast_diff.language} entities: {names}"


def _parse_json_response(raw: str) -> dict:
    """Extract JSON from LLM response, tolerating minor formatting issues."""
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
