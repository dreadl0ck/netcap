# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==1.26.0"]
# ///

import argparse
import asyncio
import hashlib
import json
import zipfile
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def replay(binary, capture, workers, compare_http):
    with TemporaryDirectory(prefix="netcap-alert-replay-") as data:
        params = StdioServerParameters(command=str(binary), args=[
            "mcp", "--bind", "127.0.0.1:0", "--quiet", "--data-dir", data,
        ], env={key: data for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME")} | {
            "NC_WORKERS": str(workers), "NC_STREAM_WORKERS": str(workers),
        })
        async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as client:
            await client.initialize()

            async def call(name, arguments):
                async with asyncio.timeout(190 if name == "wait_for_session" else 60):
                    result = await client.call_tool(name, arguments)
                if result.isError or not isinstance(result.structuredContent, dict):
                    raise ValueError(f"{name} failed or returned no structured result")
                return result.structuredContent

            uploaded = await call("ingest_pcap", {"path": str(capture)})
            args = {"session_id": uploaded["session_id"]}
            if not (await call("wait_for_session", args | {"timeout_seconds": 180}))["completed"]:
                raise ValueError("fixture did not finish")
            capture_evidence = await call("get_capture_evidence", args | {"fields": "config,status"})
            if capture_evidence["config"]["workers"] != workers or capture_evidence["status"] not in {"done", "complete"}:
                raise ValueError(f"unexpected capture evidence for {workers} workers: {capture_evidence}")
            http, http_total = [], None
            for _ in range(128 if compare_http else 0):
                response = await call("query_audit_records", args | {"type": "HTTP", "limit": 100, "offset": len(http)})
                records = response["records"]
                total = response["summary"]["total"]
                if http_total is not None and total != http_total:
                    raise ValueError("HTTP audit total changed during replay")
                http_total = total
                http.extend(json.dumps(row, sort_keys=True) for row in records)
                if len(http) == total:
                    break
                if not records or len(http) > total:
                    raise ValueError("incomplete HTTP audit pagination")
            if compare_http and (not http or len(http) != http_total):
                raise ValueError("missing HTTP audit or page budget exhausted")
            alerts, generation = [], None
            for _ in range(128):
                options = args | {"offset": len(alerts), "limit": 200}
                if generation:
                    options["generation"] = generation
                page = await call("list_alerts", options)
                if not page["generation"] or (generation and generation != page["generation"]):
                    raise ValueError("alert generation changed during replay")
                generation = page["generation"]
                alerts.extend(page["alerts"])
                if not page["has_more"]:
                    if not alerts or len(alerts) != page["totalCount"]:
                        raise ValueError("missing alerts or inconsistent total")
                    # The UI identity includes detection time and is per execution.
                    return http if compare_http else None, Counter(
                        json.dumps({k: v for k, v in alert.items() if k not in {"detectedAtNs", "alertId"}}, sort_keys=True)
                        for alert in alerts)
                if not page["alerts"] or page["next_offset"] != len(alerts):
                    raise ValueError("alert continuation did not advance")
            raise ValueError("alert page budget exhausted")


async def check(binary, capture, compare_http=True):
    baseline_http, baseline = await replay(binary, capture, 1, compare_http)
    print(json.dumps({"run": 1, "workers": 1, "alerts": baseline.total(), "http_rows": len(baseline_http) if compare_http else None}), flush=True)
    differs = False
    for run, workers in enumerate((4, 1, 4), 2):
        current_http, current = await replay(binary, capture, workers, compare_http)
        removed, added = (baseline - current).total(), (current - baseline).total()
        same_http = Counter(baseline_http) == Counter(current_http) if compare_http else None
        differs |= bool(removed or added or same_http is False)
        old, new = ([json.loads(row) for row in values.elements()] for values in (baseline, current))
        keys = sorted({key for row in old + new for key in row})
        fields = [key for key in keys if Counter(json.dumps(row.get(key), sort_keys=True) for row in old)
                  != Counter(json.dumps(row.get(key), sort_keys=True) for row in new)]
        print(json.dumps({"run": run, "workers": workers, "alerts": current.total(), "removed": removed, "added": added,
                          "changed_field_multisets": fields, "http_rows": len(current_http) if compare_http else None,
                          "http_same_multiset": same_http,
                          "http_same_order": baseline_http == current_http if compare_http else None}), flush=True)
    return not differs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare MCP alert multisets on the pinned MCP-22 capture.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--public-capture", type=Path, help="Replay the SHA-256-pinned 2018-12-18 capture instead")
    args = parser.parse_args()
    if args.public_capture is not None:
        with args.public_capture.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != "d35d186bb34fe0bf6a2e8787ebd71f44ec3ed0b90b3bbc890a97bad8823d92b8":
                raise ValueError("unexpected 2018-12-18 capture digest")
        raise SystemExit(0 if asyncio.run(check(args.binary.resolve(), args.public_capture.resolve(), compare_http=False)) else 1)
    with TemporaryDirectory(prefix="netcap-mcp22-") as directory, args.archive.open("rb") as archive:
        if hashlib.file_digest(archive, "sha256").hexdigest() != "6d5c914a95b343096f86e454ee67a122a1da47b1172dcc82d8dc39f70312133e":
            raise ValueError("unexpected v0.16.11 archive digest")
        capture = Path(directory) / "http_alerts_300.pcap"
        with zipfile.ZipFile(archive) as bundle:
            capture.write_bytes(bundle.read("netcap-v0.16.11-synthetic-repros/repro/v1611/mcp22/" + capture.name))
        raise SystemExit(0 if asyncio.run(check(args.binary.resolve(), capture)) else 1)
