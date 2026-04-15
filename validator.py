"""PatchSense OSS-CRS Validator — main entry point.

Runs as the `validator` module in the crs_run_phase. Receives patches from the
OSS-CRS exchange directory, classifies each as root-cause-fix or
symptom-suppression using PatchSense, and re-submits only confirmed
root-cause fixes to the exchange.

Architecture:
  1. Fetch all bug-candidates (SARIFs) at startup — build CWE/vuln context index.
  2. Watch the fetch directory for incoming patches (register-fetch-dir).
  3. For each patch: match to a bug-candidate, run PatchSense validation.
  4. If classified root-cause-fix above confidence threshold: submit to exchange.
  5. If symptom-suppression or uncertain: log and discard.
  6. Emit a bug-candidate SARIF with the PatchSense assessment for each patch.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("patchsense-validator")

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

TARGET = os.environ.get("OSS_CRS_TARGET", "")
HARNESS = os.environ.get("OSS_CRS_TARGET_HARNESS", "")
LLM_API_URL = os.environ.get("OSS_CRS_LLM_API_URL", "")
LLM_API_KEY = os.environ.get("OSS_CRS_LLM_API_KEY", "")
PATCHSENSE_MODEL = os.environ.get("PATCHSENSE_MODEL", "")
CONFIDENCE_THRESHOLD = float(os.environ.get("PATCHSENSE_CONFIDENCE_THRESHOLD", "0.70"))
FORWARD_UNCERTAIN = os.environ.get("PATCHSENSE_FORWARD_UNCERTAIN", "false").lower() == "true"
PATCHSENSE_TIMEOUT = int(os.environ.get("PATCHSENSE_TIMEOUT", "120"))

WORK_DIR = Path("/work")
PATCH_IN_DIR = WORK_DIR / "patches-in"        # incoming patches from exchange
BUG_CANDIDATE_DIR = WORK_DIR / "bug-candidates"
VALIDATED_DIR = WORK_DIR / "patches-validated"  # approved patches → submitted
ASSESSMENT_DIR = WORK_DIR / "assessments"        # SARIF assessments → submitted
POLL_INTERVAL = 2.0  # seconds between fetch polls


# ---------------------------------------------------------------------------
# Import PatchSense (graceful fallback if not installed in container)
# ---------------------------------------------------------------------------

try:
    from patchsense.parser.diff import parse_diff
    from patchsense.analyzer.root_cause import analyze_root_cause
    from patchsense.analyzer.alignment import verify_alignment
    from patchsense.verdicts import aggregate
    from patchsense.models import PatchClass
    from patchsense.backends.factory import default_backend
    PATCHSENSE_AVAILABLE = True
    logger.info("PatchSense loaded successfully")
except ImportError as e:
    PATCHSENSE_AVAILABLE = False
    logger.error("PatchSense not available: %s", e)


# ---------------------------------------------------------------------------
# libCRS integration
# ---------------------------------------------------------------------------

crs = None


def _init_libcrs():
    global crs
    try:
        from libCRS.base import DataType
        from libCRS.cli.main import init_crs_utils
        crs = init_crs_utils()
        return DataType
    except ImportError:
        logger.warning("libCRS not available — running in standalone mode")
        return None


def _fetch_all(data_type, dest_dir: Path) -> list[Path]:
    """Fetch all files of a given type from the exchange directory."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    if crs is None:
        return []
    try:
        fetched = crs.fetch(data_type, dest_dir)
        if fetched:
            logger.info("Fetched %d %s file(s) into %s", len(fetched), data_type, dest_dir)
        return [dest_dir / f for f in (fetched or [])]
    except Exception as e:
        logger.warning("Fetch %s failed: %s", data_type, e)
        return []


def _submit(data_type, file_path: Path) -> bool:
    """Submit a file to the exchange directory."""
    if crs is None:
        logger.info("[DRY RUN] Would submit %s as %s", file_path, data_type)
        return True
    try:
        crs.submit(data_type, file_path)
        logger.info("Submitted %s as %s", file_path.name, data_type)
        return True
    except Exception as e:
        logger.error("Submit %s failed: %s", file_path, e)
        return False


# ---------------------------------------------------------------------------
# PatchSense validation
# ---------------------------------------------------------------------------

def validate_patch(
    diff_text: str,
    vuln_desc: str = "",
    cwe: str = "",
) -> dict:
    """Run PatchSense on a patch diff and return the result dict.

    Returns:
        {
          "classification": "root-cause-fix" | "symptom-suppression" | "uncertain" | "unrelated",
          "confidence": float,
          "reasoning": str,
          "risk_flags": list[str],
          "forwarded": bool,   # True if this patch should be re-submitted
        }
    """
    if not PATCHSENSE_AVAILABLE:
        return {
            "classification": "uncertain",
            "confidence": 0.0,
            "reasoning": "PatchSense not available in this container",
            "risk_flags": ["patchsense-unavailable"],
            "forwarded": False,
        }

    try:
        # Configure backend
        backend = _build_backend()

        # Parse diff
        patch = parse_diff(diff_text)

        # Component 1: root cause analysis
        root_cause = analyze_root_cause(patch, backend=backend)

        # Component 2: alignment verification
        alignment = verify_alignment(
            patch, root_cause,
            vuln_description=vuln_desc,
            cwe=cwe,
            backend=backend,
        )

        # Aggregate into final verdict
        result = aggregate(patch, root_cause, alignment, cwe=cwe)

        classification = result.final_classification.value
        confidence = result.final_confidence

        # Decide whether to forward
        forwarded = False
        if classification == PatchClass.ROOT_CAUSE_FIX.value:
            forwarded = confidence >= CONFIDENCE_THRESHOLD
        elif classification == PatchClass.UNCERTAIN.value and FORWARD_UNCERTAIN:
            forwarded = True

        return {
            "classification": classification,
            "confidence": confidence,
            "reasoning": alignment.reasoning,
            "risk_flags": alignment.risk_flags,
            "explanation": result.explanation,
            "forwarded": forwarded,
        }

    except Exception as e:
        logger.exception("PatchSense validation failed: %s", e)
        return {
            "classification": "uncertain",
            "confidence": 0.0,
            "reasoning": f"Validation error: {e}",
            "risk_flags": ["validation-error"],
            "forwarded": False,
        }


def _build_backend():
    """Build the appropriate LLM backend.

    Priority:
    1. If OSS_CRS_LLM_API_URL is set (running inside oss-crs), use it via OpenAI backend.
    2. If PATCHSENSE_MODEL starts with "mlx:", use MLX backend.
    3. Otherwise use the default backend (from patchsense config).
    """
    if LLM_API_URL and LLM_API_KEY:
        from patchsense.backends.openai_backend import OpenAIBackend
        model = PATCHSENSE_MODEL or "patchsense-local"
        return OpenAIBackend(
            model=model,
            api_base=LLM_API_URL,
            api_key=LLM_API_KEY,
        )
    if PATCHSENSE_MODEL.startswith("mlx:"):
        from patchsense.backends.mlx_backend import MLXBackend
        return MLXBackend()
    return default_backend()


# ---------------------------------------------------------------------------
# SARIF assessment generation
# ---------------------------------------------------------------------------

def _make_assessment_sarif(
    patch_path: Path,
    validation: dict,
    cwe: str,
    vuln_desc: str,
) -> dict:
    """Generate a SARIF 2.1.0 bug-candidate documenting PatchSense's assessment."""
    classification = validation["classification"]
    confidence = validation["confidence"]
    reasoning = validation.get("reasoning", "")
    risk_flags = validation.get("risk_flags", [])
    forwarded = validation["forwarded"]

    level = "note" if forwarded else "warning"
    verdict_text = (
        f"PatchSense assessment: {classification.upper()} "
        f"(confidence={confidence:.1%}, forwarded={forwarded})\n"
        f"Reasoning: {reasoning}"
    )
    if risk_flags:
        verdict_text += f"\nRisk flags: {', '.join(risk_flags)}"

    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PatchSense",
                    "version": "2.4",
                    "informationUri": "https://github.com/aaronsrhodes/patchsense-crs",
                    "rules": [{
                        "id": cwe or "UNKNOWN",
                        "shortDescription": {
                            "text": f"Patch assessment: {classification}"
                        },
                        "fullDescription": {
                            "text": vuln_desc or f"Patch classified as {classification}",
                        },
                        "properties": {
                            "patchsense.classification": classification,
                            "patchsense.confidence": confidence,
                            "patchsense.forwarded": forwarded,
                        }
                    }]
                }
            },
            "results": [{
                "ruleId": cwe or "UNKNOWN",
                "level": level,
                "message": {"text": verdict_text},
                "relatedLocations": [{
                    "message": {"text": f"Patch file: {patch_path.name}"}
                }],
                "properties": {
                    "patch_file": patch_path.name,
                    "risk_flags": risk_flags,
                }
            }]
        }]
    }


# ---------------------------------------------------------------------------
# Main validation loop
# ---------------------------------------------------------------------------

def build_sarif_index(sarif_files: list[Path]) -> list:
    """Parse all SARIF files and return a flat list of VulnContext objects."""
    from sarif_parser import parse_sarif
    contexts = []
    for sarif_path in sarif_files:
        found = parse_sarif(sarif_path)
        if found:
            contexts.extend(found)
            logger.info("Parsed %d vuln context(s) from %s", len(found), sarif_path.name)
    logger.info("Total vuln contexts loaded: %d", len(contexts))
    return contexts


def process_patch(patch_path: Path, sarif_contexts: list, DataType) -> bool:
    """Validate one patch file and submit if it passes.

    Returns True if the patch was forwarded.
    """
    logger.info("Validating patch: %s", patch_path.name)

    try:
        diff_text = patch_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.error("Cannot read patch %s: %s", patch_path, e)
        return False

    if not diff_text.strip():
        logger.warning("Patch %s is empty, skipping", patch_path.name)
        return False

    # Match to best SARIF context
    vuln_desc = ""
    cwe = ""
    if sarif_contexts:
        from sarif_parser import match_sarif_to_diff
        ctx = match_sarif_to_diff(sarif_contexts, diff_text)
        if ctx:
            cwe = ctx.cwe
            vuln_desc = ctx.description
            logger.info(
                "Matched patch to: CWE=%s file=%s func=%s",
                cwe, ctx.file_path, ctx.function_name,
            )

    # Run PatchSense
    validation = validate_patch(diff_text, vuln_desc=vuln_desc, cwe=cwe)

    logger.info(
        "Patch %s: classification=%s confidence=%.2f forwarded=%s",
        patch_path.name,
        validation["classification"],
        validation["confidence"],
        validation["forwarded"],
    )
    if validation.get("risk_flags"):
        logger.info("Risk flags: %s", validation["risk_flags"])

    # Emit assessment SARIF
    ASSESSMENT_DIR.mkdir(parents=True, exist_ok=True)
    assessment = _make_assessment_sarif(patch_path, validation, cwe, vuln_desc)
    assessment_path = ASSESSMENT_DIR / f"{patch_path.stem}-assessment.sarif"
    assessment_path.write_text(json.dumps(assessment, indent=2))
    _submit(DataType.BUG_CANDIDATE, assessment_path)

    # Forward approved patch
    if validation["forwarded"]:
        VALIDATED_DIR.mkdir(parents=True, exist_ok=True)
        forwarded_path = VALIDATED_DIR / patch_path.name
        forwarded_path.write_bytes(patch_path.read_bytes())
        return _submit(DataType.PATCH, forwarded_path)

    logger.info(
        "Patch %s NOT forwarded (%s, confidence=%.2f)",
        patch_path.name,
        validation["classification"],
        validation["confidence"],
    )
    return False


def watch_for_patches(sarif_contexts: list, DataType) -> None:
    """Main loop: poll for new patches and validate each one."""
    seen: set[str] = set()

    logger.info(
        "Watching for patches (confidence_threshold=%.2f, forward_uncertain=%s)",
        CONFIDENCE_THRESHOLD,
        FORWARD_UNCERTAIN,
    )

    while True:
        # One-shot fetch of new patches
        try:
            new_files = crs.fetch(DataType.PATCH, PATCH_IN_DIR) if crs else []
        except Exception as e:
            logger.debug("Patch fetch: %s", e)
            new_files = []

        if new_files:
            for fname in new_files:
                patch_path = PATCH_IN_DIR / fname
                patch_hash = _file_hash(patch_path)
                if patch_hash in seen:
                    continue
                seen.add(patch_hash)
                try:
                    process_patch(patch_path, sarif_contexts, DataType)
                except Exception as e:
                    logger.exception("Error processing patch %s: %s", fname, e)

        time.sleep(POLL_INTERVAL)


def _file_hash(path: Path) -> str:
    try:
        return hashlib.blake2b(path.read_bytes(), digest_size=16).hexdigest()
    except OSError:
        return str(path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    logger.info(
        "PatchSense Validator starting: target=%s harness=%s model=%s",
        TARGET, HARNESS, PATCHSENSE_MODEL or "(default)",
    )

    if not PATCHSENSE_AVAILABLE:
        logger.error("PatchSense package not available — exiting")
        sys.exit(1)

    DataType = _init_libcrs()

    # Register log directory
    log_dir = WORK_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    if crs:
        try:
            crs.register_log_dir(log_dir)
        except Exception as e:
            logger.warning("Failed to register log dir: %s", e)

    # Fetch bug-candidates (SARIFs) at startup
    sarif_files = _fetch_all(DataType.BUG_CANDIDATE, BUG_CANDIDATE_DIR) if DataType else []
    sarif_contexts = build_sarif_index(sarif_files) if sarif_files else []

    if not sarif_contexts:
        logger.warning(
            "No bug-candidate SARIFs found at startup. "
            "PatchSense will run without CWE/vuln context (reduced accuracy)."
        )

    # Ensure work directories exist
    PATCH_IN_DIR.mkdir(parents=True, exist_ok=True)

    # Start register-fetch-dir daemon for continuous patch delivery
    if crs:
        fetch_proc = subprocess.Popen(
            ["libCRS", "register-fetch-dir", "--log", str(WORK_DIR / "fetch.log"),
             "patch", str(PATCH_IN_DIR)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.info("libCRS register-fetch-dir started (pid=%d)", fetch_proc.pid)

    # Main validation loop (runs until container is killed by framework)
    watch_for_patches(sarif_contexts, DataType)


if __name__ == "__main__":
    main()
