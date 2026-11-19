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


async def replay(binary, capture):
    with TemporaryDirectory(prefix="netcap-alert-replay-") as data:
        params = StdioServerParameters(command=str(binary), args=[
            "mcp", "--bind", "127.0.0.1:0", "--quiet", "--data-dir", data,
        ], env={key: data for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME")})
        async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as client:
            await client.initialize()

            async def call(name, arguments):
                async with asyncio.timeout(60):
                    result = await client.call_tool(name, arguments)
                if result.isError or not isinstance(result.structuredContent, dict):
                    raise ValueError(f"{name}: {result.content}")
                return result.structuredContent

            uploaded = await call("ingest_pcap", {"path": str(capture)})
            args = {"session_id": uploaded["session_id"]}
            if not (await call("wait_for_session", args | {"timeout_seconds": 45}))["completed"]:
                raise ValueError("fixture did not finish")
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
                    return Counter(json.dumps({k: v for k, v in alert.items() if k != "detectedAtNs"}, sort_keys=True)
                                   for alert in alerts)
                if not page["alerts"] or page["next_offset"] != len(alerts):
                    raise ValueError("alert continuation did not advance")
            raise ValueError("alert page budget exhausted")


async def check(binary, capture):
    baseline = await replay(binary, capture)
    print(json.dumps({"run": 1, "alerts": baseline.total()}), flush=True)
    differs = False
    for run in range(2, 5):
        current = await replay(binary, capture)
        removed, added = (baseline - current).total(), (current - baseline).total()
        differs |= bool(removed or added)
        old, new = ([json.loads(row) for row in values.elements()] for values in (baseline, current))
        keys = sorted({key for row in old + new for key in row})
        fields = [key for key in keys if Counter(json.dumps(row.get(key), sort_keys=True) for row in old)
                  != Counter(json.dumps(row.get(key), sort_keys=True) for row in new)]
        print(json.dumps({"run": run, "alerts": current.total(), "removed": removed, "added": added,
                          "changed_field_multisets": fields}), flush=True)
    return not differs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare MCP alert multisets on the pinned MCP-22 capture.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="netcap-mcp22-") as directory, args.archive.open("rb") as archive:
        if hashlib.file_digest(archive, "sha256").hexdigest() != "6d5c914a95b343096f86e454ee67a122a1da47b1172dcc82d8dc39f70312133e":
            raise ValueError("unexpected v0.16.11 archive digest")
        capture = Path(directory) / "http_alerts_300.pcap"
        with zipfile.ZipFile(archive) as bundle:
            capture.write_bytes(bundle.read("netcap-v0.16.11-synthetic-repros/repro/v1611/mcp22/" + capture.name))
        raise SystemExit(0 if asyncio.run(check(args.binary.resolve(), capture)) else 1)
