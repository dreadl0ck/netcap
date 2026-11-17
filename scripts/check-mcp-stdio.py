# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==1.26.0", "jsonschema==4.26.0"]
# ///

import argparse
import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from jsonschema import validate
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


GLOBAL_READS = """
get_analysis_settings get_analyst_capabilities
get_bpf_config get_capability_inventory get_decoder_config get_features
get_live_capture_status get_operator_bindings get_protobuf_status
list_decoders list_network_interfaces list_offline_rule_packs list_protobuf_messages
""".split()

SESSION_READS = """
get_audit_record_values get_protocol_hierarchy get_session_info get_timeline_meta
get_alert_stats get_analysis_config get_yara_status list_rules list_yara_rules
get_capture_evidence get_artifact_analysis get_behavior get_behavior_health
get_reproduction_metadata get_network_detection get_behavior_topology
list_alerts list_alerts_grouped list_audit_records list_connections list_devices
list_domains list_extracted_files list_fingerprints list_hosts list_http_records
list_secrets list_services list_software list_vulnerabilities
""".split()


async def check(binary, capture, data_dir):
    params = StdioServerParameters(command=str(binary), args=[
        "mcp", "--bind", "127.0.0.1:0", "--quiet", "--pcap", str(capture),
        "--data-dir", data_dir, "--behavior", "--behavior-prefix", "192.168.0.0/16",
    ], env={"HOME": data_dir, "XDG_CONFIG_HOME": data_dir, "XDG_DATA_HOME": data_dir})
    async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as client:
        await client.initialize()
        tools = {}
        cursor = None
        while True:
            page = await client.list_tools(cursor=cursor)
            for tool in page.tools:
                if tool.name in tools:
                    raise ValueError(f"duplicate tool: {tool.name}")
                tools[tool.name] = tool
            cursor = page.nextCursor
            if not cursor:
                break
        covered, failures = set(), []
        successes = 0

        async def call(name, arguments):
            nonlocal successes
            tool = tools[name]
            validate(arguments, tool.inputSchema)
            async with asyncio.timeout(30):
                result = await client.call_tool(name, arguments)
            if result.isError:
                raise ValueError(result.content[0].text if result.content else "tool returned an error")
            if tool.outputSchema is None or not isinstance(result.structuredContent, dict):
                raise ValueError("success lacks an advertised structured object contract")
            validate(result.structuredContent, tool.outputSchema)
            covered.add(name)
            successes += 1
            return result.structuredContent

        async with asyncio.timeout(30):
            while True:
                index = await call("list_sessions", {})
                ready = [s for s in index["sessions"] if s.get("completed") and s.get("input_name") == capture.name]
                if ready:
                    sid = ready[0]["session_id"]
                    break
                await asyncio.sleep(0.2)

        args = {"session_id": sid}
        cases = [(name, {}) for name in GLOBAL_READS]
        cases += [(name, args) for name in SESSION_READS if name != "get_audit_record_values"]
        cases += [
            ("get_audit_record_values", args | {"type": "UDP"}),
            ("get_investigation_health", args | {"kind": "reassembly"}),
            ("get_audit_record_fields", {"type": "UDP"}),
            ("wait_for_session", args | {"timeout_seconds": 2}),
        ]
        for name, arguments in cases:
            try:
                result = await call(name, arguments)
                if name == "get_session_info":
                    status = result["audit_stats"]
                    if status.get("analysisPhase") != "completed" or not status.get("timelineGeneration"):
                        raise ValueError("completed session lost its timeline generation")
            except Exception as exc:
                failures.append(f"{name}: {exc}")

        query = args | {"type": "UDP"}
        first = await call("query_audit_records", query | {"allow_partial": True, "limit": 1})
        summary = first["summary"]
        second = await call("query_audit_records", query | {
            "allow_partial": True, "limit": 1, "offset": 1,
            "run_id": summary["runId"], "stage_generation": summary["stageGeneration"],
            "query_generation": summary["queryGeneration"],
        })
        for changed in ({"fields": "SrcIP"}, {"filter": "true"}):
            rejected = await client.call_tool("query_audit_records", query | {
                "allow_partial": True, "offset": 1, "run_id": summary["runId"],
                "stage_generation": summary["stageGeneration"],
                "query_generation": summary["queryGeneration"],
            } | changed)
            if not rejected.isError:
                failures.append(f"sealed continuation accepted changed query: {changed}")
        count = await call("query_audit_records", query | {"count_only": True})
        if (not summary["partialAdmission"] or first["records"] == second["records"]
                or count["summary"]["total"] != 18 or "records" in count):
            raise ValueError("fixture query count or sealed continuation differs")
        empty = await call("query_audit_records", query | {"offset": 18})
        if empty["records"] != []:
            raise ValueError("empty page did not return an array")

        for name in ("get_network_detection", "get_behavior_health"):
            result = await client.call_tool(name, {"session_id": "unknown-contract-session"})
            if not result.isError:
                failures.append(f"{name}: unknown session unexpectedly succeeded")

        print(json.dumps({"advertised": len(tools), "covered_count": len(covered), "covered": sorted(covered),
                          "successes": successes, "uncovered": sorted(tools.keys() - covered),
                          "failures": failures}, indent=2))
        return not failures


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check Netcap's stdio tool contracts on the mDNS fixture.")
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parents[1] / "internal/collector/testdata/voip/mdns.pcap"
    with TemporaryDirectory(prefix="netcap-mcp-contracts-") as data_dir:
        raise SystemExit(0 if asyncio.run(check(args.binary.resolve(), fixture, data_dir)) else 1)
