"""Repository scanner — walks a codebase and finds vulnerability candidates.

This is the "point at a repo, get results" entry point. It:
  1. Discovers source files in supported languages
  2. Runs source pattern detection on each
  3. Confirms candidates with LLM analysis
  4. Generates PR-ready fix packages for confirmed findings
  5. Produces a summary report

Designed for scanning publicly available open-source code.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from patchsense.analyzer.detect import detect_vulnerabilities
from patchsense.analyzer.proof import PRPackage, generate_pr_package
from patchsense.analyzer.source_patterns import detect_language
from patchsense.models import VulnerabilityCandidate, VulnerabilityReport
from patchsense.backends.base import LLMBackend


# File extensions we know how to analyze
_SUPPORTED_EXTENSIONS: dict[str, str] = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".java": "java",
}

# Directories to skip — vendor code, tests, build artifacts, etc.
_SKIP_DIRS: set[str] = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "third_party", "third-party", "3rdparty",
    "build", "dist", "out", "target", "cmake-build-debug", "cmake-build-release",
    "__pycache__", ".tox", ".eggs",
    ".idea", ".vscode", ".settings",
}

# Don't scan files larger than this (likely generated or data files)
_MAX_FILE_SIZE = 500_000  # 500KB


@dataclass
class ScanFinding:
    """A single confirmed vulnerability finding from a scan."""
    candidate: VulnerabilityCandidate
    package: PRPackage | None = None
    source_file: str = ""
    language: str = ""


@dataclass
class ScanResult:
    """Complete result from scanning a repository."""
    root_dir: str
    files_scanned: int = 0
    files_with_findings: int = 0
    total_candidates: int = 0
    findings: list[ScanFinding] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    scan_time_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def findings_by_severity(self) -> dict[str, list[ScanFinding]]:
        """Group findings by severity (high, medium, low)."""
        groups: dict[str, list[ScanFinding]] = {
            "high": [], "medium": [], "low": [],
        }
        for f in self.findings:
            if f.candidate.confidence >= 0.8:
                groups["high"].append(f)
            elif f.candidate.confidence >= 0.6:
                groups["medium"].append(f)
            else:
                groups["low"].append(f)
        return groups

    def findings_by_family(self) -> dict[str, list[ScanFinding]]:
        """Group findings by vulnerability family."""
        groups: dict[str, list[ScanFinding]] = {}
        for f in self.findings:
            fam = f.candidate.family
            if fam not in groups:
                groups[fam] = []
            groups[fam].append(f)
        return groups


def discover_source_files(
    root: Path,
    *,
    extensions: dict[str, str] | None = None,
    skip_dirs: set[str] | None = None,
    max_file_size: int = _MAX_FILE_SIZE,
) -> list[tuple[Path, str]]:
    """Walk a directory tree and find scannable source files.

    Returns list of (file_path, language) tuples, sorted by path.
    """
    exts = extensions or _SUPPORTED_EXTENSIONS
    skip = skip_dirs or _SKIP_DIRS
    results = []

    for path in sorted(root.rglob("*")):
        # Skip directories in the exclusion list (check relative path only)
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if any(part in skip for part in rel.parts):
            continue

        if not path.is_file():
            continue

        suffix = path.suffix.lower()
        if suffix not in exts:
            continue

        # Skip oversized files
        try:
            if path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue

        results.append((path, exts[suffix]))

    return results


def scan_repository(
    root: Path,
    *,
    backend: LLMBackend | None = None,
    family: str | None = None,
    confirm_with_llm: bool = True,
    generate_packages: bool = True,
    min_confidence: float = 0.6,
    progress_callback=None,
) -> ScanResult:
    """Scan a repository for vulnerability patterns.

    Args:
        root: Root directory of the repository to scan.
        backend: LLM backend for confirmation + fix generation.
            Required if confirm_with_llm=True or generate_packages=True.
        family: Restrict to a specific vulnerability family.
        confirm_with_llm: Use LLM to filter false positives.
        generate_packages: Generate PR-ready fix packages for confirmed findings.
        min_confidence: Minimum confidence to include in results.
        progress_callback: Optional callable(file_path, file_index, total_files)
            for progress reporting.

    Returns:
        ScanResult with all findings and metadata.
    """
    start = time.time()
    result = ScanResult(root_dir=str(root))

    # Step 1: Discover files
    source_files = discover_source_files(root)
    total = len(source_files)

    files_with_candidates: set[str] = set()

    # Step 2: Scan each file
    for idx, (file_path, language) in enumerate(source_files):
        if progress_callback:
            progress_callback(str(file_path), idx, total)

        try:
            source_text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.errors.append(f"{file_path}: {e}")
            continue

        result.files_scanned += 1

        # Run detection
        try:
            report = detect_vulnerabilities(
                source_text,
                file_path=str(file_path.relative_to(root)),
                family=family,
                backend=backend if confirm_with_llm else None,
                confirm_with_llm=confirm_with_llm,
            )
        except Exception as e:
            result.errors.append(f"{file_path}: detection error: {e}")
            continue

        if not report.candidates:
            continue

        files_with_candidates.add(str(file_path))

        for candidate in report.candidates:
            if candidate.confidence < min_confidence:
                continue

            result.total_candidates += 1

            finding = ScanFinding(
                candidate=candidate,
                source_file=str(file_path.relative_to(root)),
                language=language,
            )

            # Generate PR package if requested and confidence is high enough
            if generate_packages and backend and candidate.confidence >= min_confidence:
                try:
                    finding.package = generate_pr_package(
                        candidate, source_text, backend
                    )
                except Exception as e:
                    result.errors.append(
                        f"{file_path}: PR generation error: {e}"
                    )

            result.findings.append(finding)

    result.files_with_findings = len(files_with_candidates)
    result.scan_time_seconds = time.time() - start
    return result


def write_scan_results(
    scan_result: ScanResult,
    output_dir: Path,
) -> dict[str, Path]:
    """Write all scan results and PR packages to an output directory.

    Directory structure:
        output_dir/
            SCAN_REPORT.md          — Human-readable summary
            scan_results.json       — Machine-readable results
            findings/
                001_buffer-overflow_parser.c/
                    PR_DESCRIPTION.md
                    fix.patch
                    test_vulnerability.c
                    test_fix.c
                002_injection_UserDAO.java/
                    ...

    Returns dict of artifact_name → file_path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, Path] = {}

    # Write JSON results
    json_path = output_dir / "scan_results.json"
    json_data = {
        "root_dir": scan_result.root_dir,
        "files_scanned": scan_result.files_scanned,
        "files_with_findings": scan_result.files_with_findings,
        "total_candidates": scan_result.total_candidates,
        "scan_time_seconds": round(scan_result.scan_time_seconds, 2),
        "findings": [
            {
                "source_file": f.source_file,
                "language": f.language,
                "family": f.candidate.family,
                "cwe": f.candidate.cwe,
                "confidence": f.candidate.confidence,
                "line_range": list(f.candidate.line_range),
                "patterns": f.candidate.source_patterns,
                "description": f.candidate.description,
                "has_fix_package": f.package is not None,
            }
            for f in scan_result.findings
        ],
        "errors": scan_result.errors,
    }
    json_path.write_text(__import__("json").dumps(json_data, indent=2))
    files["scan_results"] = json_path

    # Write markdown report
    report_path = output_dir / "SCAN_REPORT.md"
    report_path.write_text(_build_scan_report(scan_result))
    files["scan_report"] = report_path

    # Write individual PR packages
    findings_dir = output_dir / "findings"
    for i, finding in enumerate(scan_result.findings, 1):
        if finding.package is None:
            continue

        # Build a readable directory name
        source_name = Path(finding.source_file).stem
        pkg_dir_name = f"{i:03d}_{finding.candidate.family}_{source_name}"
        pkg_dir = findings_dir / pkg_dir_name

        pkg_files = finding.package.write_to_directory(pkg_dir)
        for name, path in pkg_files.items():
            files[f"finding_{i}_{name}"] = path

    return files


def _build_scan_report(scan_result: ScanResult) -> str:
    """Build a markdown scan report."""
    lines = []
    lines.append(f"# PatchSense Scan Report\n")
    lines.append(f"**Repository**: `{scan_result.root_dir}`")
    lines.append(f"**Files scanned**: {scan_result.files_scanned}")
    lines.append(f"**Files with findings**: {scan_result.files_with_findings}")
    lines.append(f"**Total findings**: {scan_result.total_candidates}")
    lines.append(f"**Scan time**: {scan_result.scan_time_seconds:.1f}s\n")

    if not scan_result.findings:
        lines.append("No vulnerabilities detected.\n")
        return "\n".join(lines)

    # Summary by severity
    by_severity = scan_result.findings_by_severity()
    lines.append("## Summary\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    for sev in ("high", "medium", "low"):
        count = len(by_severity.get(sev, []))
        if count:
            lines.append(f"| {sev.upper()} | {count} |")
    lines.append("")

    # Summary by family
    by_family = scan_result.findings_by_family()
    lines.append("## Findings by Family\n")
    lines.append(f"| Family | Count | Files |")
    lines.append(f"|--------|-------|-------|")
    for fam, findings in sorted(by_family.items()):
        fam_files = set(f.source_file for f in findings)
        lines.append(f"| {fam} | {len(findings)} | {', '.join(sorted(fam_files))} |")
    lines.append("")

    # Detail for each finding
    lines.append("## Findings Detail\n")
    for i, finding in enumerate(scan_result.findings, 1):
        c = finding.candidate
        lines.append(f"### {i}. {c.family} in `{finding.source_file}`\n")
        lines.append(f"- **Lines**: {c.line_range[0]}–{c.line_range[1]}")
        lines.append(f"- **Confidence**: {c.confidence:.0%}")
        lines.append(f"- **CWE**: {c.cwe or 'N/A'}")
        lines.append(f"- **Patterns**: {', '.join(c.source_patterns)}")
        lines.append(f"- **Description**: {c.description}")
        if finding.package:
            lines.append(f"- **Fix package**: `findings/{i:03d}_{c.family}_{Path(finding.source_file).stem}/`")
        lines.append("")

    if scan_result.errors:
        lines.append("## Errors\n")
        for err in scan_result.errors:
            lines.append(f"- {err}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by PatchSense. Review all findings carefully before acting on them.*")
    return "\n".join(lines)
