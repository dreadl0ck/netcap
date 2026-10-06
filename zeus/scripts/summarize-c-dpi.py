#!/usr/bin/env python3
"""Summarize matched C-integration benchmark samples; raw files remain the evidence."""

import json
import pathlib
import re
import statistics
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(r"^(Benchmark\S+)\s+\d+\s+(.+)$")


def benchmarks(name):
    samples = {}
    for line in (root / name).read_text().splitlines():
        match = pattern.match(line)
        if not match:
            continue
        fields = match[2].split()
        metrics = {fields[i + 1]: float(fields[i]) for i in range(0, len(fields), 2)}
        samples.setdefault(match[1], []).append(metrics)
    if not samples:
        raise ValueError(f"No benchmark samples in {name}")
    return {
        key: {"samples": len(values), **{
            metric: statistics.median(sample[metric] for sample in values)
            for metric in values[0]
        }} for key, values in samples.items()
    }


def rss(name):
    text = (root / name).read_text()
    match = re.search(r"(\d+)\s+maximum resident set size", text)
    if match:
        return int(match[1])
    match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
    if match:
        return int(match[1]) * 1024
    raise ValueError(f"No RSS measurement in {name}")


integration = {mode: benchmarks(f"c-dpi-{mode}.txt") for mode in ("legacy-safe", "budget", "incremental")}
comparison = {}
for key, baseline in integration["legacy-safe"].items():
    optimized = integration["incremental"][key]
    capped = integration["budget"][key]
    comparison[key] = {
        "speedup_vs_replay": baseline["ns/op"] / optimized["ns/op"],
        "speedup_vs_budget_only": capped["ns/op"] / optimized["ns/op"],
        "go_allocated_bytes_reduction": 1 - optimized["B/op"] / baseline["B/op"],
    }

report = {
    "environment": (root / "c-dpi-environment.txt").read_text().splitlines(),
    "baseline": "Legacy classification/replay architecture with native deallocation corrected; original baseline captured separately before fixes.",
    "workload": "Decoded synthetic midstream TCP flows, 512-flow batches; shared_packet models three enrichment calls per decoded packet.",
    "integration": integration,
    "comparison": comparison,
    "native_scaling": {mode: benchmarks(f"c-dpi-native-{mode}.txt") for mode in ("legacy-safe", "incremental")},
    "hot_exhausted_flows": {mode: benchmarks(f"c-dpi-hot-{mode}.txt") for mode in ("legacy-safe", "incremental")},
    "rss_bytes": {
        f"{shape}/{mode}": rss(f"c-dpi-memory-{shape}-{mode}.txt")
        for shape in ("churn", "short") for mode in ("legacy-safe", "incremental-1", "incremental-8")
    },
    "memory_workloads": {"churn": "40 batches of 256 ten-packet flows, flushed per batch", "short": "32768 distinct single-packet flows"},
    "caveats": [
        "B/op and allocs/op measure Go allocations only; RSS includes native state and contexts.",
        "Each independent nDPI context adds fixed native memory; dpi-workers=1 is the low-memory setting.",
        "Small unidentified first IP packets (<=512 bytes) are replayed once on second-packet promotion; later packets are incremental.",
        "Hot-flow scaling measures exhausted-state lookups; fresh-flow scaling is measured separately at the native wrapper.",
        "Native classification work ends after ten eligible observations; consecutive duplicate enrichment calls are coalesced.",
        "Legacy LPI caches UNKNOWN/NO_PAYLOAD/generic UDP results; corrected incremental state can therefore do more useful inspection.",
    ],
}
(root / "c-dpi-summary.json").write_text(json.dumps(report, indent=2) + "\n")
for key, values in comparison.items():
    print(f"{key}: {values['speedup_vs_replay']:.2f}x replay, {values['speedup_vs_budget_only']:.2f}x budget-only")
for key, value in report["rss_bytes"].items():
    print(f"RSS {key}: {value / 1048576:.1f} MiB")
