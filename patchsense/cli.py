"""PatchSense CLI — validate semantic correctness of AI-generated vulnerability patches."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from patchsense.models import InfoLevel, PatchClass
from patchsense.parser.diff import parse_patch
from patchsense.parser.ast_diff import extract_ast_diff
from patchsense.analyzer.root_cause import extract_root_cause
from patchsense.analyzer.alignment import verify_alignment
from patchsense.verdicts import aggregate
from patchsense.backends.factory import get_backend, default_backend

app = typer.Typer(
    name="patchsense",
    help="Semantic patch correctness validator for AI-generated vulnerability patches.",
    add_completion=False,
)
console = Console()

_MODEL_HELP = (
    "Model to use. Format: provider:model. "
    "Examples: 'ollama:qwen2.5-coder:32b', 'anthropic:claude-opus-4-6'. "
    "Defaults to best available (Ollama if running, else Anthropic)."
)


@app.command()
def validate(
    diff: Optional[Path] = typer.Option(
        None, "--diff", "-d",
        help="Path to a .patch or .diff file. Use '-' to read from stdin.",
    ),
    vuln: str = typer.Option(
        "", "--vuln", "-v",
        help="Vulnerability description (natural language).",
    ),
    cwe: str = typer.Option(
        "", "--cwe", "-c",
        help="CWE identifier, e.g. CWE-122 (optional).",
    ),
    original: Optional[Path] = typer.Option(
        None, "--original", "-o",
        help="Path to original (pre-patch) source file for enhanced AST analysis (optional).",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help=_MODEL_HELP,
    ),
    output_json: bool = typer.Option(
        False, "--json", "-j",
        help="Output results as JSON instead of rich text.",
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key",
        help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var).",
        envvar="ANTHROPIC_API_KEY",
    ),
) -> None:
    """Validate whether a patch genuinely fixes the root cause of a vulnerability."""
    # Read diff
    if diff is None or str(diff) == "-":
        diff_text = sys.stdin.read()
    else:
        if not diff.exists():
            console.print(f"[red]Error:[/red] diff file not found: {diff}")
            raise typer.Exit(1)
        diff_text = diff.read_text(encoding="utf-8", errors="replace")

    if not diff_text.strip():
        console.print("[red]Error:[/red] empty patch provided")
        raise typer.Exit(1)

    # Read original source (optional)
    original_source: Optional[str] = None
    if original and original.exists():
        original_source = original.read_text(encoding="utf-8", errors="replace")

    # Resolve backend
    try:
        backend = get_backend(model, api_key) if model else default_backend(api_key)
    except RuntimeError as e:
        console.print(f"[red]Backend error:[/red] {e}")
        raise typer.Exit(1)

    if not output_json:
        console.print(f"[bold]PatchSense[/bold] — {backend.name}\n")

    with console.status("[cyan]Parsing patch...[/cyan]", spinner="dots") if not output_json else _noop():
        parsed = parse_patch(diff_text)
        ast_diff = extract_ast_diff(parsed, original_source)

    if not output_json:
        console.print(f"  Parsed: {parsed.summary}")
        if ast_diff.function_names:
            console.print(f"  Functions: {', '.join(ast_diff.function_names)}")

    with console.status("[cyan]Component 1: Extracting root cause...[/cyan]", spinner="dots") if not output_json else _noop():
        root_cause = extract_root_cause(parsed, ast_diff, vuln, cwe, backend)

    with console.status("[cyan]Component 2: Verifying alignment...[/cyan]", spinner="dots") if not output_json else _noop():
        alignment = verify_alignment(parsed, root_cause, vuln, cwe, backend)

    result = aggregate(parsed, root_cause, alignment, cwe=cwe)

    if output_json:
        print(json.dumps(result.model_dump(), indent=2))
    else:
        _render_result(result)

    raise typer.Exit(0 if result.passed else 1)


_INFO_LEVEL_HELP = (
    "How much vulnerability context to give the LLM. "
    "'blind' = diff only, no hints. "
    "'minimal' = short one-line hint, no CWE. "
    "'full' = full description + CWE (default)."
)


@app.command()
def batch(
    manifest: Path = typer.Argument(
        ..., help="JSON file listing patches to evaluate. See docs for format."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write results to this JSON file."
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help=_MODEL_HELP,
    ),
    info_level: InfoLevel = typer.Option(
        InfoLevel.FULL, "--info-level", "-i", help=_INFO_LEVEL_HELP,
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="ANTHROPIC_API_KEY",
    ),
) -> None:
    """Evaluate multiple patches from a manifest file (for AIxCC archive evaluation)."""
    if not manifest.exists():
        console.print(f"[red]Error:[/red] manifest not found: {manifest}")
        raise typer.Exit(1)

    items = json.loads(manifest.read_text())

    try:
        backend = get_backend(model, api_key) if model else default_backend(api_key)
    except RuntimeError as e:
        console.print(f"[red]Backend error:[/red] {e}")
        raise typer.Exit(1)

    level_label = {
        InfoLevel.BLIND: "BLIND (diff only)",
        InfoLevel.MINIMAL: "MINIMAL (one-line hint)",
        InfoLevel.FULL: "FULL (description + CWE)",
    }[info_level]
    console.print(f"[bold]PatchSense batch[/bold] — {backend.name} — {len(items)} cases — {level_label}\n")

    results = []
    passed = failed = uncertain = 0

    table = Table(box=box.SIMPLE, show_header=True)
    table.add_column("ID", style="dim", width=12)
    table.add_column("Classification", width=22)
    table.add_column("Confidence", justify="right", width=10)
    table.add_column("Flags", width=30)

    for item in items:
        item_id = item.get("id", "?")
        diff_text = Path(item["diff"]).read_text() if "diff" in item else item.get("diff_text", "")

        # Select vulnerability context based on info level
        if info_level == InfoLevel.BLIND:
            vuln_desc = ""
            cwe = ""
        elif info_level == InfoLevel.MINIMAL:
            vuln_desc = item.get("vuln_minimal", "")
            cwe = ""
        else:  # InfoLevel.FULL
            vuln_desc = item.get("vuln", "")
            cwe = item.get("cwe", "")

        original_source = None
        if "original" in item:
            p = Path(item["original"])
            if p.exists():
                original_source = p.read_text()

        with console.status(f"[cyan]Evaluating {item_id}...[/cyan]", spinner="dots"):
            parsed = parse_patch(diff_text)
            ast_diff = extract_ast_diff(parsed, original_source)
            root_cause = extract_root_cause(parsed, ast_diff, vuln_desc, cwe, backend)
            alignment = verify_alignment(parsed, root_cause, vuln_desc, cwe, backend)
            result = aggregate(parsed, root_cause, alignment, cwe=cwe)

        cls = result.final_classification
        if cls == PatchClass.ROOT_CAUSE_FIX:
            passed += 1; color = "green"
        elif cls == PatchClass.UNCERTAIN:
            uncertain += 1; color = "yellow"
        else:
            failed += 1; color = "red"

        gt = item.get("ground_truth", "")
        correct = "✓" if cls.value == gt else "✗"

        table.add_row(
            item_id,
            f"[{color}]{cls.value}[/{color}]  {correct}",
            f"{result.final_confidence:.2f}",
            ", ".join(result.alignment_verdict.risk_flags[:2]) or "-",
        )

        results.append({
            "id": item_id,
            "classification": cls.value,
            "ground_truth": gt,
            "correct": cls.value == gt,
            "confidence": result.final_confidence,
            "risk_flags": result.alignment_verdict.risk_flags,
            "reasoning": result.alignment_verdict.reasoning,
            "model": backend.name,
            "info_level": info_level.value,
        })

    console.print(table)

    correct_count = sum(1 for r in results if r["correct"])
    console.print(
        f"\nTotal: {len(results)}  "
        f"[green]Pass: {passed}[/green]  "
        f"[red]Fail: {failed}[/red]  "
        f"[yellow]Uncertain: {uncertain}[/yellow]  "
        f"Accuracy: {correct_count}/{len(results)} ({correct_count/len(results):.0%})"
    )

    if output:
        output.write_text(json.dumps(results, indent=2))
        console.print(f"\nResults written to {output}")


def _render_result(result) -> None:
    cls = result.final_classification
    color_map = {
        PatchClass.ROOT_CAUSE_FIX: "green",
        PatchClass.SYMPTOM_SUPPRESSION: "red",
        PatchClass.UNRELATED: "red",
        PatchClass.UNCERTAIN: "yellow",
    }
    color = color_map[cls]

    verdict_panel = Panel(
        f"[bold {color}]{cls.value.upper()}[/bold {color}]\n"
        f"Confidence: {result.final_confidence:.2f}\n\n"
        f"{result.explanation}",
        title="PatchSense Verdict",
        border_style=color,
    )
    console.print(verdict_panel)

    if result.alignment_verdict.risk_flags:
        console.print("\n[bold yellow]Risk flags:[/bold yellow]")
        for flag in result.alignment_verdict.risk_flags:
            console.print(f"  • {flag}")


@app.command()
def suggest(
    diff: Optional[Path] = typer.Option(
        None, "--diff", "-d",
        help="Path to a .patch or .diff file.",
    ),
    vuln: str = typer.Option(
        "", "--vuln", "-v",
        help="Vulnerability description.",
    ),
    cwe: str = typer.Option(
        "", "--cwe", "-c",
        help="CWE identifier, e.g. CWE-122.",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help=_MODEL_HELP,
    ),
    verify: bool = typer.Option(
        False, "--verify",
        help="Re-run PatchSense on the suggestion to self-validate.",
    ),
    output_json: bool = typer.Option(
        False, "--json", "-j",
        help="Output results as JSON.",
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="ANTHROPIC_API_KEY",
    ),
) -> None:
    """Suggest a root-cause fix for a patch classified as symptom-suppression."""
    from patchsense.analyzer.suggest import suggest_fix, verify_suggestion

    if diff is None or str(diff) == "-":
        diff_text = sys.stdin.read()
    else:
        diff_text = diff.read_text(encoding="utf-8", errors="replace")

    try:
        backend = get_backend(model, api_key) if model else default_backend(api_key)
    except RuntimeError as e:
        console.print(f"[red]Backend error:[/red] {e}")
        raise typer.Exit(1)

    if not output_json:
        console.print(f"[bold]PatchSense suggest[/bold] — {backend.name}\n")

    # Step 1: Classify the patch
    with console.status("[cyan]Classifying patch...[/cyan]", spinner="dots") if not output_json else _noop():
        parsed = parse_patch(diff_text)
        ast_diff = extract_ast_diff(parsed, None)
        root_cause = extract_root_cause(parsed, ast_diff, vuln, cwe, backend)
        alignment = verify_alignment(parsed, root_cause, vuln, cwe, backend)
        result = aggregate(parsed, root_cause, alignment)

    if result.final_classification == PatchClass.ROOT_CAUSE_FIX:
        if output_json:
            print(json.dumps({"status": "already-root-cause-fix", "confidence": result.final_confidence}))
        else:
            console.print("[green]This patch is already classified as a root-cause fix.[/green]")
        raise typer.Exit(0)

    # Step 2: Generate suggestion
    with console.status("[cyan]Generating fix suggestion...[/cyan]", spinner="dots") if not output_json else _noop():
        suggestion = suggest_fix(parsed, result, vuln, cwe, backend)

    # Step 3: Self-validate if requested
    if verify and suggestion.suggested_diff:
        with console.status("[cyan]Self-validating suggestion...[/cyan]", spinner="dots") if not output_json else _noop():
            suggestion = verify_suggestion(suggestion, vuln, cwe, backend)

    if output_json:
        print(json.dumps(suggestion.model_dump(), indent=2))
    else:
        _render_suggestion(suggestion)


@app.command()
def detect(
    source: Path = typer.Option(
        ..., "--source", "-s",
        help="Path to source file to scan for vulnerabilities.",
    ),
    family: Optional[str] = typer.Option(
        None, "--family", "-f",
        help="Restrict to a specific vulnerability family (e.g., buffer-overflow).",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help=_MODEL_HELP,
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Directory to write PR-ready fix packages.",
    ),
    output_json: bool = typer.Option(
        False, "--json", "-j",
        help="Output results as JSON.",
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="ANTHROPIC_API_KEY",
    ),
) -> None:
    """Detect vulnerabilities in source code and generate fix packages."""
    from patchsense.analyzer.detect import detect_vulnerabilities
    from patchsense.analyzer.proof import generate_pr_package

    if not source.exists():
        console.print(f"[red]Error:[/red] source file not found: {source}")
        raise typer.Exit(1)

    source_text = source.read_text(encoding="utf-8", errors="replace")

    try:
        backend = get_backend(model, api_key) if model else default_backend(api_key)
    except RuntimeError as e:
        console.print(f"[red]Backend error:[/red] {e}")
        raise typer.Exit(1)

    if not output_json:
        console.print(f"[bold]PatchSense detect[/bold] — {backend.name}")
        console.print(f"Source: {source}\n")

    with console.status("[cyan]Scanning for vulnerabilities...[/cyan]", spinner="dots") if not output_json else _noop():
        report = detect_vulnerabilities(
            source_text,
            file_path=str(source),
            family=family,
            backend=backend,
        )

    if not report.candidates:
        if output_json:
            print(json.dumps({"status": "clean", "candidates": []}))
        else:
            console.print("[green]No vulnerabilities detected.[/green]")
        raise typer.Exit(0)

    # Generate PR packages for confirmed vulnerabilities
    packages = []
    for candidate in report.candidates:
        if candidate.confidence >= 0.6:
            with console.status(f"[cyan]Generating fix for {candidate.family}...[/cyan]", spinner="dots") if not output_json else _noop():
                pkg = generate_pr_package(candidate, source_text, backend)
                packages.append(pkg)

    if output_json:
        print(json.dumps({
            "status": "vulnerabilities_found",
            "candidates": [c.model_dump() for c in report.candidates],
            "packages": len(packages),
        }, indent=2))
    else:
        _render_detection_report(report, packages)

    # Write PR packages to disk if output dir specified
    if output_dir and packages:
        for i, pkg in enumerate(packages):
            pkg_dir = output_dir / f"vuln_{i + 1}_{pkg.family}"
            files = pkg.write_to_directory(pkg_dir)
            if not output_json:
                console.print(f"\n[bold]PR package written to {pkg_dir}/[/bold]")
                for name, path in files.items():
                    console.print(f"  {name}: {path}")


@app.command()
def scan(
    source_dir: Path = typer.Argument(
        ..., help="Root directory of the repository to scan.",
    ),
    family: Optional[str] = typer.Option(
        None, "--family", "-f",
        help="Restrict to a specific vulnerability family (e.g., buffer-overflow).",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help=_MODEL_HELP,
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Directory to write scan report and PR-ready fix packages.",
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help="Skip LLM confirmation (faster, more false positives).",
    ),
    no_packages: bool = typer.Option(
        False, "--no-packages",
        help="Skip PR package generation (just report findings).",
    ),
    min_confidence: float = typer.Option(
        0.6, "--min-confidence",
        help="Minimum confidence threshold for findings (0.0–1.0).",
    ),
    output_json: bool = typer.Option(
        False, "--json", "-j",
        help="Output results as JSON.",
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", envvar="ANTHROPIC_API_KEY",
    ),
) -> None:
    """Scan a repository for vulnerability patterns and generate fix packages.

    Walks the directory tree, finds C/C++/Java source files, detects vulnerability
    patterns, confirms with LLM analysis, and generates PR-ready fix suggestions.

    Example:
        patchsense scan ./nginx --output ./results
        patchsense scan ./project --family buffer-overflow --no-llm
    """
    from patchsense.analyzer.scan import (
        scan_repository,
        discover_source_files,
        write_scan_results,
    )

    if not source_dir.is_dir():
        console.print(f"[red]Error:[/red] not a directory: {source_dir}")
        raise typer.Exit(1)

    # Resolve backend
    backend = None
    if not no_llm or not no_packages:
        try:
            backend = get_backend(model, api_key) if model else default_backend(api_key)
        except RuntimeError as e:
            if no_llm:
                backend = None  # OK if we're not using LLM
            else:
                console.print(f"[red]Backend error:[/red] {e}")
                raise typer.Exit(1)

    if not output_json:
        model_name = backend.name if backend else "no LLM"
        console.print(f"[bold]PatchSense scan[/bold] — {model_name}")
        console.print(f"Target: {source_dir.resolve()}\n")

        # Show file discovery
        source_files = discover_source_files(source_dir)
        lang_counts: dict[str, int] = {}
        for _, lang in source_files:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        lang_summary = ", ".join(f"{count} {lang}" for lang, count in sorted(lang_counts.items()))
        console.print(f"  Found {len(source_files)} source files ({lang_summary})\n")

    def _progress(file_path: str, idx: int, total: int):
        if not output_json:
            short = Path(file_path).name
            console.print(f"  [{idx + 1}/{total}] {short}", end="\r")

    with console.status("[cyan]Scanning repository...[/cyan]", spinner="dots") if not output_json else _noop():
        result = scan_repository(
            source_dir,
            backend=backend,
            family=family,
            confirm_with_llm=not no_llm,
            generate_packages=not no_packages,
            min_confidence=min_confidence,
            progress_callback=_progress if not output_json else None,
        )

    if output_json:
        import json as json_mod
        print(json_mod.dumps({
            "root": str(source_dir),
            "files_scanned": result.files_scanned,
            "files_with_findings": result.files_with_findings,
            "total_findings": result.total_candidates,
            "scan_time": round(result.scan_time_seconds, 2),
            "findings": [
                {
                    "file": f.source_file,
                    "family": f.candidate.family,
                    "cwe": f.candidate.cwe,
                    "confidence": f.candidate.confidence,
                    "lines": list(f.candidate.line_range),
                    "patterns": f.candidate.source_patterns,
                    "description": f.candidate.description,
                }
                for f in result.findings
            ],
        }, indent=2))
    else:
        _render_scan_result(result)

    # Write outputs if requested
    if output_dir:
        files = write_scan_results(result, output_dir)
        if not output_json:
            console.print(f"\n[bold]Results written to {output_dir}/[/bold]")
            console.print(f"  Report: {files.get('scan_report', '')}")
            console.print(f"  Data: {files.get('scan_results', '')}")
            pkg_count = sum(1 for k in files if k.startswith("finding_"))
            if pkg_count:
                console.print(f"  Fix packages: {pkg_count} artifacts")

    if result.has_findings:
        raise typer.Exit(1)  # Non-zero exit = findings detected
    raise typer.Exit(0)


@app.command()
def invariants(
    family: Optional[str] = typer.Option(
        None, "--family", "-f",
        help="Show invariants for a specific family only.",
    ),
) -> None:
    """Display computed family pattern invariants."""
    invariants_path = Path(__file__).parent.parent / "data" / "family_invariants.json"
    if not invariants_path.exists():
        console.print("[red]Error:[/red] family_invariants.json not found. Run data/compute_invariants.py first.")
        raise typer.Exit(1)

    data = json.loads(invariants_path.read_text())

    table = Table(box=box.SIMPLE, show_header=True, title="Family Pattern Invariants")
    table.add_column("Family", style="bold", width=18)
    table.add_column("N (fixes)", justify="right", width=10)
    table.add_column("Disjunctive Invariant", width=50)
    table.add_column("Strong Signals", width=30)
    table.add_column("Anti-Patterns", width=25)

    for fam_name, fam_data in sorted(data.items()):
        if family and fam_name != family:
            continue

        n = fam_data.get("min_examples", 0)
        sufficient = fam_data.get("sufficient_data", False)
        disj = ", ".join(fam_data.get("disjunctive_invariant", [])) or "-"
        strong = ", ".join(fam_data.get("strong_fix_signals", [])) or "-"
        anti = ", ".join(fam_data.get("anti_patterns", [])) or "-"

        color = "green" if sufficient else "dim"
        table.add_row(
            f"[{color}]{fam_name}[/{color}]",
            f"[{color}]{n}[/{color}]",
            disj if sufficient else f"[dim]insufficient data[/dim]",
            strong if sufficient else "-",
            anti if sufficient else "-",
        )

    console.print(table)


def _render_suggestion(suggestion) -> None:
    """Render a fix suggestion as rich text."""
    console.print(Panel(
        f"[bold]Family:[/bold] {suggestion.family}\n"
        f"[bold]Original classification:[/bold] {suggestion.original_classification.value}\n"
        f"[bold]Missing fix signals:[/bold] {', '.join(suggestion.missing_fix_signals) or 'none'}\n"
        f"[bold]Suppression signals:[/bold] {', '.join(suggestion.present_suppress_signals) or 'none'}\n\n"
        f"[bold]Suggested approach:[/bold]\n{suggestion.suggested_approach}\n\n"
        f"[bold]Confidence:[/bold] {suggestion.confidence:.2f}"
        + (f"\n[bold]Self-validation:[/bold] {suggestion.self_validation.value}" if suggestion.self_validation else ""),
        title="Fix Suggestion",
        border_style="cyan",
    ))

    if suggestion.suggested_diff:
        console.print("\n[bold]Suggested diff:[/bold]")
        console.print(Panel(suggestion.suggested_diff, border_style="dim"))


def _render_detection_report(report, packages) -> None:
    """Render a detection report as rich text."""
    table = Table(box=box.SIMPLE, show_header=True, title="Detected Vulnerabilities")
    table.add_column("Family", style="bold", width=18)
    table.add_column("Lines", width=12)
    table.add_column("Patterns", width=35)
    table.add_column("Confidence", justify="right", width=10)
    table.add_column("Description", width=40)

    for c in report.candidates:
        color = "red" if c.confidence >= 0.7 else "yellow" if c.confidence >= 0.5 else "dim"
        table.add_row(
            f"[{color}]{c.family}[/{color}]",
            f"{c.line_range[0]}-{c.line_range[1]}",
            ", ".join(c.source_patterns[:3]),
            f"[{color}]{c.confidence:.2f}[/{color}]",
            c.description[:60],
        )

    console.print(table)

    if packages:
        console.print(f"\n[bold green]{len(packages)} PR-ready fix package(s) generated.[/bold green]")
        console.print("[dim]Use --output to write packages to disk.[/dim]")
    else:
        console.print("\n[dim]No high-confidence candidates for PR generation.[/dim]")


def _render_scan_result(result) -> None:
    """Render a repository scan result as rich text."""
    console.print(f"\n[bold]Scan complete[/bold] — "
                  f"{result.files_scanned} files in {result.scan_time_seconds:.1f}s\n")

    if not result.findings:
        console.print("[green]No vulnerabilities detected.[/green]")
        return

    # Summary table
    table = Table(box=box.SIMPLE, show_header=True, title="Scan Findings")
    table.add_column("#", width=4)
    table.add_column("File", style="bold", width=30)
    table.add_column("Family", width=18)
    table.add_column("Lines", width=12)
    table.add_column("Confidence", justify="right", width=10)
    table.add_column("Description", width=45)

    for i, finding in enumerate(result.findings, 1):
        c = finding.candidate
        color = "red" if c.confidence >= 0.8 else "yellow" if c.confidence >= 0.6 else "dim"
        fix_icon = " [green]+fix[/green]" if finding.package else ""
        table.add_row(
            str(i),
            finding.source_file,
            f"[{color}]{c.family}[/{color}]",
            f"{c.line_range[0]}-{c.line_range[1]}",
            f"[{color}]{c.confidence:.0%}[/{color}]",
            c.description[:60] + fix_icon,
        )

    console.print(table)

    # Summary counts
    by_severity = result.findings_by_severity()
    high = len(by_severity.get("high", []))
    med = len(by_severity.get("medium", []))
    low = len(by_severity.get("low", []))
    pkg_count = sum(1 for f in result.findings if f.package)

    console.print(
        f"\n  [red]High: {high}[/red]  [yellow]Medium: {med}[/yellow]  "
        f"[dim]Low: {low}[/dim]  "
        f"[green]Fix packages: {pkg_count}[/green]"
    )

    if pkg_count:
        console.print("\n[dim]Use --output to write PR-ready fix packages to disk.[/dim]")

    if result.errors:
        console.print(f"\n[yellow]{len(result.errors)} error(s) during scan:[/yellow]")
        for err in result.errors[:5]:
            console.print(f"  [dim]{err}[/dim]")


class _noop:
    """No-op context manager used when output_json=True."""
    def __enter__(self): return self
    def __exit__(self, *_): pass


if __name__ == "__main__":
    app()
