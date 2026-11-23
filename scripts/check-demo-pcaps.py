# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==1.26.0"]
# ///
"""Analyze captures through the MCP/WebUI pipeline the try demo uses.

Every input must reach a completed session. A partial-coverage capture may
complete with a coverage note; any analysis error fails the check.
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

QUIET = [] if __import__("os").environ.get("NETCAP_DEMO_VERBOSE") else ["--quiet"]


async def analyze(binary, capture, timeout):
    with TemporaryDirectory(prefix="netcap-demo-") as data_dir:
        params = StdioServerParameters(command=str(binary), args=[
            "mcp", "--bind", "127.0.0.1:0", *QUIET, "--pcap", str(capture), "--data-dir", data_dir,
        ], env={"HOME": data_dir, "XDG_CONFIG_HOME": data_dir, "XDG_DATA_HOME": data_dir})
        started = time.monotonic()
        async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as client:
            await client.initialize()
            async with asyncio.timeout(timeout):
                while True:
                    result = await client.call_tool("list_sessions", {})
                    if result.isError:
                        raise ValueError(result.content[0].text)
                    for session in result.structuredContent["sessions"]:
                        # Upload names replace spaces with underscores.
                        if session.get("input_name") not in (capture.name, capture.name.replace(" ", "_")):
                            continue
                        if session.get("error"):
                            return {"status": "error", "error": session["error"]}
                        if session.get("completed"):
                            return {"status": "completed", "coverage": session.get("coverage"),
                                    "seconds": round(time.monotonic() - started, 1)}
                    await asyncio.sleep(1)


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("captures", type=Path, nargs="+")
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args()
    failed = False
    for capture in args.captures:
        try:
            outcome = await analyze(args.binary.resolve(), capture.resolve(), args.timeout)
        except Exception as exc:  # noqa: BLE001 - report and continue with the next capture
            outcome = {"status": "error", "error": repr(exc)}
        failed |= outcome["status"] != "completed"
        print(json.dumps({"capture": capture.name, **outcome}), flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
