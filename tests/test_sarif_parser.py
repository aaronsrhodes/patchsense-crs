"""Tests for sarif_parser.py.

Covers ASan crash format, static analysis SARIF format, CWE extraction,
function name extraction from stack traces, and diff-to-SARIF matching.
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Run from repo root: pytest tests/test_sarif_parser.py
sys.path.insert(0, str(Path(__file__).parent.parent))
from sarif_parser import parse_sarif, match_sarif_to_diff, VulnContext


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_sarif(data: dict) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False)
    json.dump(data, f)
    f.close()
    return Path(f.name)


ASAN_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "AddressSanitizer", "rules": [{
            "id": "CWE-121",
            "shortDescription": {"text": "Stack-based buffer overflow in png_handle_iCCP"},
        }]}},
        "results": [{
            "ruleId": "CWE-121",
            "level": "error",
            "message": {"text": (
                "AddressSanitizer: dynamic-stack-buffer-overflow on address 0x7fff03213192 "
                "at pc 0x559972f1e42a bp 0x7fff03213110\n"
                "    #0 0x559972f1e429 in png_handle_iCCP /src/libpng/pngrutil.c:1457:13\n"
                "    #1 0x559972ef1dcd in OSS_FUZZ_png_read_info /src/libpng/pngread.c:229:10\n"
                "    #2 0x559972e454ae in LLVMFuzzerTestOneInput /src/fuzz.cc:156:3"
            )},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "/src/libpng/pngrutil.c"},
                "region": {"startLine": 1457, "startColumn": 13},
            }}],
        }],
    }],
}

STATIC_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "CodeScan++", "rules": [{
            "id": "CWE-502",
            "shortDescription": {"text": "Deserialization of Untrusted Data"},
            "fullDescription": {"text": "The product deserializes untrusted data..."},
        }]}},
        "results": [{
            "ruleId": "CWE-502",
            "level": "warning",
            "message": {"text": "A crafted set of transactions can trigger unsafe deserialization."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "DataTree.java"},
                    "region": {"startLine": 537, "startColumn": 5},
                },
                "logicalLocations": [{"kind": "function", "name": "verifyDataIntegrity"}],
            }],
        }],
    }],
}


# ---------------------------------------------------------------------------
# ASan format tests
# ---------------------------------------------------------------------------

class TestAsanSarif:
    def setup_method(self):
        self.path = _write_sarif(ASAN_SARIF)
        self.results = parse_sarif(self.path)
        self.ctx = self.results[0]

    def teardown_method(self):
        self.path.unlink(missing_ok=True)

    def test_one_result(self):
        assert len(self.results) == 1

    def test_cwe_extracted(self):
        assert self.ctx.cwe == "CWE-121"

    def test_file_path(self):
        assert self.ctx.file_path == "/src/libpng/pngrutil.c"

    def test_start_line(self):
        assert self.ctx.start_line == 1457

    def test_function_from_asan_trace(self):
        # Function name comes from ASan stack trace (no logicalLocations in this SARIF)
        assert self.ctx.function_name == "png_handle_iCCP"

    def test_tool_name(self):
        assert self.ctx.tool_name == "AddressSanitizer"

    def test_description_contains_asan_output(self):
        assert "buffer-overflow" in self.ctx.description.lower()


# ---------------------------------------------------------------------------
# Static analysis SARIF tests
# ---------------------------------------------------------------------------

class TestStaticSarif:
    def setup_method(self):
        self.path = _write_sarif(STATIC_SARIF)
        self.results = parse_sarif(self.path)
        self.ctx = self.results[0]

    def teardown_method(self):
        self.path.unlink(missing_ok=True)

    def test_cwe_extracted(self):
        assert self.ctx.cwe == "CWE-502"

    def test_function_from_logical_locations(self):
        assert self.ctx.function_name == "verifyDataIntegrity"

    def test_start_line(self):
        assert self.ctx.start_line == 537

    def test_file_path(self):
        assert self.ctx.file_path == "DataTree.java"


# ---------------------------------------------------------------------------
# CWE extraction edge cases
# ---------------------------------------------------------------------------

class TestCweExtraction:
    def _parse_with_rule(self, rule_id: str, extra_rule_fields: dict = None) -> VulnContext:
        rule = {"id": rule_id, **(extra_rule_fields or {})}
        data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test", "rules": [rule]}},
            "results": [{"ruleId": rule_id, "level": "warning",
                "message": {"text": "desc"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.c"},
                    "region": {"startLine": 1}}}]}]}]}
        path = _write_sarif(data)
        try:
            return parse_sarif(path)[0]
        finally:
            path.unlink(missing_ok=True)

    def test_cwe_directly_in_rule_id(self):
        ctx = self._parse_with_rule("CWE-476")
        assert ctx.cwe == "CWE-476"

    def test_cwe_case_insensitive(self):
        ctx = self._parse_with_rule("cwe-476")
        assert ctx.cwe == "CWE-476"

    def test_short_id_with_cwe_in_description(self):
        ctx = self._parse_with_rule(
            "buffer-overflow",
            {"shortDescription": {"text": "CWE-121 buffer overflow"}},
        )
        assert ctx.cwe == "CWE-121"

    def test_empty_rule_id_no_cwe(self):
        data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": []}},
            "results": [{"ruleId": "", "level": "warning", "message": {"text": "x"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.c"},
                    "region": {"startLine": 1}}}]}]}]}
        path = _write_sarif(data)
        try:
            ctx = parse_sarif(path)[0]
        finally:
            path.unlink(missing_ok=True)
        assert ctx.cwe == ""


# ---------------------------------------------------------------------------
# Diff matching tests
# ---------------------------------------------------------------------------

class TestDiffMatching:
    def setup_method(self):
        self.path = _write_sarif(ASAN_SARIF)
        self.contexts = parse_sarif(self.path)

    def teardown_method(self):
        self.path.unlink(missing_ok=True)

    def test_exact_path_match(self):
        diff = "--- a/src/libpng/pngrutil.c\n+++ b/src/libpng/pngrutil.c\n@@ -1457 +1457 @@\n"
        matched = match_sarif_to_diff(self.contexts, diff)
        assert matched is not None
        assert matched.cwe == "CWE-121"

    def test_filename_only_match(self):
        # Diff uses different prefix but same filename
        diff = "--- a/pngrutil.c\n+++ b/pngrutil.c\n@@ -1 +1 @@\n"
        matched = match_sarif_to_diff(self.contexts, diff)
        assert matched is not None

    def test_no_match_returns_first(self):
        # When no path matches, returns first entry as fallback
        diff = "--- a/completely_different.c\n+++ b/completely_different.c\n"
        matched = match_sarif_to_diff(self.contexts, diff)
        assert matched is not None  # fallback

    def test_empty_contexts_returns_none(self):
        diff = "--- a/f.c\n+++ b/f.c\n"
        assert match_sarif_to_diff([], diff) is None

    def test_empty_diff_returns_first(self):
        matched = match_sarif_to_diff(self.contexts, "")
        assert matched is not None


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_invalid_json_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.sarif"
        bad.write_text("not json")
        assert parse_sarif(bad) == []

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_sarif(tmp_path / "nonexistent.sarif") == []

    def test_empty_json_returns_empty(self, tmp_path):
        empty = tmp_path / "empty.sarif"
        empty.write_text("{}")
        assert parse_sarif(empty) == []

    def test_no_results_returns_empty(self, tmp_path):
        data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": []}},
            "results": []}]}
        sarif = tmp_path / "empty_results.sarif"
        sarif.write_text(json.dumps(data))
        assert parse_sarif(sarif) == []
