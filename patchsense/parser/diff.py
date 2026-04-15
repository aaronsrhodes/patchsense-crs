"""Unified diff parser — extracts hunks and structural metadata from patch files."""

from __future__ import annotations

import re
from pathlib import Path

from unidiff import PatchSet, PatchedFile

from patchsense.models import Hunk, ParsedPatch


def parse_patch(diff_text: str) -> ParsedPatch:
    """Parse a unified diff string into a structured ParsedPatch."""
    patch_set = PatchSet(diff_text)

    hunks: list[Hunk] = []
    files_changed: list[str] = []
    total_added = 0
    total_removed = 0

    for patched_file in patch_set:
        file_path = _normalize_path(patched_file.path)
        files_changed.append(file_path)

        for hunk in patched_file:
            removed = [line.value.rstrip("\n") for line in hunk if line.is_removed]
            added = [line.value.rstrip("\n") for line in hunk if line.is_added]
            context = [line.value.rstrip("\n") for line in hunk if line.is_context]

            # Split context into before/after the changed lines
            context_before: list[str] = []
            context_after: list[str] = []
            in_change = False
            saw_change = False
            for line in hunk:
                if line.is_removed or line.is_added:
                    in_change = True
                    saw_change = True
                elif line.is_context:
                    if saw_change:
                        context_after.append(line.value.rstrip("\n"))
                    else:
                        context_before.append(line.value.rstrip("\n"))

            total_added += len(added)
            total_removed += len(removed)

            hunks.append(Hunk(
                file_path=file_path,
                start_line_original=hunk.source_start,
                start_line_patched=hunk.target_start,
                removed_lines=removed,
                added_lines=added,
                context_before=context_before,
                context_after=context_after,
            ))

    summary = _build_summary(files_changed, total_added, total_removed)

    return ParsedPatch(
        raw_diff=diff_text,
        hunks=hunks,
        files_changed=files_changed,
        lines_added=total_added,
        lines_removed=total_removed,
        summary=summary,
    )


def parse_patch_file(path: str | Path) -> ParsedPatch:
    """Parse a .patch or .diff file from disk."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_patch(text)


def _normalize_path(path: str) -> str:
    """Strip a/ b/ prefixes from git diff paths."""
    path = re.sub(r"^[ab]/", "", path)
    return path


def _build_summary(files: list[str], added: int, removed: int) -> str:
    file_count = len(files)
    noun = "file" if file_count == 1 else "files"
    return (
        f"Changes {file_count} {noun} (+{added} -{removed} lines): "
        + ", ".join(files[:3])
        + ("..." if file_count > 3 else "")
    )


def format_patch_for_llm(patch: ParsedPatch, max_lines: int = 200) -> str:
    """Render a patch in a compact form suitable for LLM context."""
    lines: list[str] = [patch.summary, ""]

    total = 0
    for hunk in patch.hunks:
        if total >= max_lines:
            lines.append(f"... ({len(patch.hunks)} hunks total, truncated)")
            break

        lines.append(f"--- {hunk.file_path} (line {hunk.start_line_original})")
        for ctx in hunk.context_before[-3:]:
            lines.append(f"  {ctx}")
        for rem in hunk.removed_lines:
            lines.append(f"- {rem}")
            total += 1
        for add in hunk.added_lines:
            lines.append(f"+ {add}")
            total += 1
        for ctx in hunk.context_after[:3]:
            lines.append(f"  {ctx}")
        lines.append("")

    return "\n".join(lines)
