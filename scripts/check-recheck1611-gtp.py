# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==1.26.0", "jsonschema==4.26.0"]
# ///

import argparse
import asyncio
import hashlib
import json
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from jsonschema import validate
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check(binary, root, fixtures):
    data = root / "data"
    params = StdioServerParameters(command=str(binary), args=[
        "mcp", "--bind", "127.0.0.1:0", "--quiet", "--data-dir", str(data),
    ], env={name: str(root) for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME")})
    async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as client:
        await client.initialize()
        tools = {}
        cursor = None
        while True:
            page = await client.list_tools(cursor=cursor)
            tools.update((tool.name, tool) for tool in page.tools)
            cursor = page.nextCursor
            if not cursor:
                break

        async def call(name, arguments):
            validate(arguments, tools[name].inputSchema)
            async with asyncio.timeout(30):
                result = await client.call_tool(name, arguments)
            if result.isError or result.structuredContent is None:
                raise ValueError(f"{name}: {result.content}")
            validate(result.structuredContent, tools[name].outputSchema)
            return result.structuredContent

        for path, message_types in fixtures:
            upload = await call("ingest_pcap", {"path": str(path)})
            args = {"session_id": upload["session_id"]}
            status = await call("wait_for_session", args | {"timeout_seconds": 15})
            if not status["completed"]:
                raise ValueError(f"{path.name}: capture did not complete: {status}")
            query = args | {"type": "GTP", "limit": len(message_types) + 1}
            ordinary = await call("query_audit_records", query)
            sealed = await call("query_audit_records", query | {"allow_partial": True})
            records = sealed["records"]
            summary = sealed["summary"]
            if (sorted(row["MessageType"] for row in records) != message_types
                    or summary["total"] != len(message_types) or summary.get("coverage") != "complete"
                    or ordinary["records"] != records or ordinary["summary"]["total"] != len(message_types)
                    or ordinary["terminal"] != "complete"):
                raise ValueError(f"{path.name}: ordinary and sealed GTP results disagree with fixture: {ordinary}, {sealed}")
            print(json.dumps({"fixture": path.name, "messageTypes": message_types, "coverage": summary["coverage"]}))


def main():
    parser = argparse.ArgumentParser(description="Check sealed GTP control audits through MCP stdio.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--public-coverage", type=Path, help="Path to the pinned gtp_coverage.pcap")
    parser.add_argument("--public-control", type=Path, help="Path to the pinned gtp10_not_0xff.pcap")
    args = parser.parse_args()
    with TemporaryDirectory(prefix="netcap-gtp-mcp-") as directory, args.archive.open("rb") as archive:
        if hashlib.file_digest(archive, "sha256").hexdigest() != "6d5c914a95b343096f86e454ee67a122a1da47b1172dcc82d8dc39f70312133e":
            raise ValueError("unexpected v0.16.11 synthetic archive digest")
        root = Path(directory)
        fixtures = []
        with zipfile.ZipFile(archive) as bundle:
            for name, message_type in (
                ("gtpu_type_01.pcap", 1),
                ("gtpu_type_02.pcap", 2),
                ("gtpu_type_1a.pcap", 26),
                ("gtpu_type_1f.pcap", 31),
                ("gtpu_type_fe.pcap", 254),
                ("gtpu_endmarker_only.pcap", 254),
                ("gtpu_tpdu_then_endmarker.pcap", 254),
            ):
                path = root / name
                path.write_bytes(bundle.read("netcap-v0.16.11-synthetic-repros/repro/v1611/gtp/" + name))
                fixtures.append((path, [message_type]))
        for path, digest, message_types in (
            (args.public_coverage, "f5fb49c12aa9c99f6492c46ee354f57999ee47388d5414f8e5c2bf2c214ee742", [1, 2, 26, 31, 254]),
            (args.public_control, "34c99bc77f398902eb74b4745f3be00ce961b57474f8352aaf54c05531be0790", [1, 2, 26]),
        ):
            if path is None:
                continue
            with path.open("rb") as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != digest:
                    raise ValueError(f"{path.name}: unexpected public capture digest")
            fixtures.append((path.resolve(), message_types))
        asyncio.run(check(args.binary.resolve(), root, fixtures))


if __name__ == "__main__":
    main()
