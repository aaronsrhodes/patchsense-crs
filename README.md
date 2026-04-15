# patchsense-crs

**OSS-CRS submission** — semantic patch correctness validator for AI-generated vulnerability fixes.

PatchSense acts as a post-generation filter in an OSS-CRS ensemble. It receives patches from the exchange directory, classifies each as **root-cause-fix** or **symptom-suppression**, and re-submits only confirmed root-cause fixes. This prevents semantically incorrect patches from being accepted as valid fixes.

---

## The Problem

37.7%–45.6% of AI-generated patches that pass all automated tests are semantically incorrect ([SoK paper, arxiv.org/abs/2602.07666](https://arxiv.org/abs/2602.07666)). Standard CRS validation — compile + run test suite + check PoV — cannot distinguish:

- A patch that **fixes the root cause** (correct)
- A patch that **adds a null guard at a call site** while leaving the defective allocation untouched (symptom suppression — still exploitable via other paths)

PatchSense addresses this gap.

---

## Performance

Evaluated on 66 held-out cases (33 root-cause-fix + 33 symptom-suppression) derived from AIxCC competition test data:

| Metric | Value | Target |
|--------|:-----:|:------:|
| Accuracy | 84.8% (56/66) | >85% |
| **Precision (RC-fix)** | **96.0% (24/25)** | **>95% ✓** |
| Recall (RC-fix) | 72.7% (24/33) | >85% |
| False Positive Rate | 3.0% (1/33) | <3% |
| F1 Score | 0.828 | — |

**Head-to-head vs. AIxCC top 5** (precision — "when you certify a patch as correct, is it correct?"):

| System | Patches Certified | Correct | Precision |
|--------|:-----------------:|:-------:|:---------:|
| Shellphish ARTIPHISHELL | 11 | 11 | 100%* |
| **PatchSense v2.4** | **24** | **23** | **96.0%** |
| Team Atlanta ATLANTIS | 31 | 26 | 83.8% |
| Trail of Bits Buttercup | 19 | 15 | 79.2% |
| Theori RoboDuck | 20 | 6 | 31.7% |

*Shellphish's 100% is from extreme selectivity (only submitted 11/28 found vulns).

---

## How It Works

### OSS-CRS Integration (Path A — Validator Plugin)

```
[Detection CRS]     →  POVs + bug-candidates → exchange dir
[Fixing CRS]        →  patches               → exchange dir
[PatchSense CRS]    ←  reads patches + bug-candidates from exchange dir
                    →  validated root-cause-fix patches → exchange dir
                    →  SARIF assessment reports         → exchange dir
```

At startup, PatchSense:
1. Fetches all bug-candidate SARIFs — builds a CWE/vulnerability context index
2. Registers a fetch-dir daemon watching for incoming patches
3. For each patch: matches to best-fit SARIF context, runs full PatchSense analysis
4. If classified as **root-cause-fix** with confidence ≥ threshold: re-submits to exchange
5. If **symptom-suppression** or **uncertain**: logs assessment and discards
6. Emits a SARIF bug-candidate with the full assessment for each validated patch

### PatchSense Analysis Pipeline

```
[Patch diff]  →  [Root Cause Extractor]  →  [Alignment Verifier]  →  [Aggregator]  →  verdict
                    (structural patterns)     (LLM + family context    (CWE-aware
                    (15 boolean signals)       + fix-assignment         confidence
                                               evidence)                scoring)
```

- **Root Cause Extractor**: Detects 15 structural diff patterns (bounds checks, allocation changes, null-after-free, etc.)
- **Alignment Verifier**: LLM-based assessment with CWE family context and empirical fix-pattern evidence from 800+ labeled CVE fixes
- **Aggregator**: CWE-aware confidence scoring — for families where defensive coding IS the canonical fix (buffer-overflow, null-deref, use-after-free), guard patterns are not penalized
- **Model**: Qwen 2.5 Coder 32B + LoRA fine-tune on 23 CWE families (val loss 0.132), or any OpenAI-compatible model via LiteLLM

---

## Ensemble Configuration

```yaml
# crs-compose.yaml excerpt
crs-libfuzzer:          # finds crashes → POVs
  cpuset: "2-5"
  memory: "8G"

patchsense-crs:         # validates patches from any bug-fixing CRS
  source:
    url: https://github.com/aaronsrhodes/patchsense-crs.git
    ref: main
  cpuset: "6-7"
  memory: "16G"
  llm_budget: 50
  additional_env:
    PATCHSENSE_CONFIDENCE_THRESHOLD: "0.75"
```

See `oss-crs/example-compose.yaml` for a complete configuration example.

---

## Repository Structure

```
patchsense-crs/
├── oss-crs/
│   ├── crs.yaml              # OSS-CRS manifest
│   ├── docker-bake.hcl       # prepare phase
│   ├── base.Dockerfile       # base image (Python 3.12 + PatchSense)
│   ├── builder.Dockerfile    # target build phase
│   ├── validator.Dockerfile  # run phase
│   ├── example-compose.yaml  # local dev config
│   └── litellm-config.yaml   # model routing (local Qwen or cloud)
├── validator.py              # main entry point
├── sarif_parser.py           # SARIF 2.1.0 parser
├── bin/compile_target        # build phase script
├── tests/
│   └── test_sarif_parser.py  # 24 tests
├── registry/
│   └── patchsense-crs.yaml   # ossf/oss-crs registry entry
└── pyproject.toml
```

---

## Supported Targets

| Attribute | Values |
|-----------|--------|
| Mode | `full`, `delta` |
| Language | `c`, `c++`, `jvm` |
| Sanitizer | `address`, `undefined` |
| Architecture | `x86_64` |

---

## License

MIT
