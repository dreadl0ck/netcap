# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==1.26.0", "jsonschema==4.26.0"]
# ///

import argparse
import asyncio
import base64
import hashlib
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
        meta = await call("get_timeline_meta", args)
        track = args | {"types": "UDP", "generation": meta["generation"]}
        page = await call("query_timeline_events", track | {"limit": 5})
        seen = []
        while True:
            if page["generation"] != meta["generation"] or page["matchCount"] != 18:
                raise ValueError("UDP timeline generation or match count changed")
            seen.extend(event["id"] for event in page["events"])
            if not page["hasMore"]:
                break
            if not page["events"] or len(seen) >= 18:
                raise ValueError("UDP timeline cursor did not advance")
            page = await call("query_timeline_events", track | {"limit": 5, "after": page["events"][-1]["cursor"]})
        if len(seen) != 18 or len(set(seen)) != 18:
            raise ValueError("UDP timeline lost or duplicated an event")
        buckets = await call("get_timeline_buckets", track | {"buckets": 4})
        series, = buckets["series"]
        if buckets["generation"] != meta["generation"] or series["type"] != "UDP" or sum(series["counts"]) != 18:
            raise ValueError("timeline buckets disagree with the paged UDP track")
        binding = await call("get_analyst_binding", {"sessionId": sid})
        source = {"sessionId": sid, "binding": binding}
        log_selection = {"source": source, "file": "collector.log", "start": 1, "end": 1}
        review = await call("review_diagnostic_log", log_selection)
        line, = review["lines"]
        if (review["binding"] != binding or review["state"] != "preview"
                or set(line) != {"ordinal", "sha256", "classes"} or line["ordinal"] != 1
                or len(line["sha256"]) != 64):
            raise ValueError("diagnostic preview lost its bounded line projection")
        stale_review = review | {"projectionSHA256": "0" * 64}
        rejected = await client.call_tool("review_diagnostic_log", log_selection | {"approve": stale_review})
        if not rejected.isError:
            raise ValueError("changed diagnostic projection accepted")
        approved = await call("review_diagnostic_log", log_selection | {"approve": review})
        if approved.get("state") != "reviewed":
            raise ValueError("diagnostic review was not confirmed")
        await call("inspect_bound_capture", {"source": source})
        await call("analyst_workspace", {"source": source, "expectedRevision": 0})
        refs = (await call("list_bound_occurrences", {"source": source, "type": "UDP"}))["references"]
        if len(refs) != 18 or any(ref["binding"] != binding for ref in refs):
            raise ValueError("UDP occurrences lost capture binding or records")
        resolved = await call("resolve_audit_occurrence", {"source": source, "reference": refs[-1]})
        if resolved["reference"] != refs[-1] or not resolved["record"]:
            raise ValueError("resolved record lost its occurrence reference")
        stale = refs[-1] | {"recordSHA256": "0" * 64}
        rejected = await client.call_tool("resolve_audit_occurrence", {"source": source, "reference": stale})
        if not rejected.isError:
            raise ValueError("changed record digest accepted")
        connections = await call("query_audit_records", args | {"type": "Connection", "filter": "TransportProto == 'UDP'", "limit": 1})
        endpoint = connections["records"][0]["SrcIP"]
        row = connections["records"][0]
        tuple_args = {"src_ip": endpoint, "src_port": str(row["SrcPort"]),
                      "dst_ip": row["DstIP"], "dst_port": str(row["DstPort"]), "protocol": "UDP"}
        for name, selector in (("carve_subpcap_for_host", {"host": endpoint}),
                               ("carve_subpcap_for_connection", tuple_args)):
            carved = await call(name, args | selector | {"run_id": binding["runId"]})
            artifact = carved["resource_uri"].rsplit("/", 1)[-1]
            wire = bytearray()
            while True:
                page = await call("read_mcp_artifact", args | {"artifact_id": artifact, "offset": len(wire), "limit": 512})
                chunk = base64.b64decode(page["data"], validate=True)
                if (page["offset"] != len(wire) or page["sha256"] != carved["sha256"]
                        or not chunk or len(chunk) > 512 or len(wire) + len(chunk) > carved["size_bytes"]):
                    raise ValueError(f"{name}: inconsistent artifact page")
                wire.extend(chunk)
                if not page["has_more"]:
                    break
            if len(wire) != carved["size_bytes"] or len(wire) <= 24 or hashlib.sha256(wire).hexdigest() != carved["sha256"]:
                raise ValueError(f"{name}: incomplete carved capture")
            denied = await client.call_tool("read_mcp_artifact", {"artifact_id": artifact, "session_id": "unrelated"})
            if not denied.isError:
                raise ValueError("carved artifact readable under a different session")
        catalogue = await call("query_capture_catalogue", {
            "sources": [source], "query": {"kind": "endpoint", "value": endpoint, "types": ["Connection"]},
        })
        if not catalogue["occurrences"] or any(row["reference"]["binding"] != binding for row in catalogue["occurrences"]):
            raise ValueError("catalogue lost fixture endpoint or occurrence binding")
        cases = [(name, {}) for name in GLOBAL_READS]
        cases += [(name, args) for name in SESSION_READS if name != "get_audit_record_values"]
        cases += [
            ("get_audit_record_values", args | {"type": "UDP"}),
            ("get_investigation_health", args | {"kind": "reassembly"}),
            ("query_flows", args | {"startNs": meta["minTime"], "endNs": meta["maxTime"], "limit": 3}),
            ("list_auth_activity", args | {"limit": 5}),
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

        uploaded = (await call("ingest_pcap", {"path": str(capture)}))["session_id"]
        if not uploaded or uploaded == sid:
            raise ValueError("upload did not create a distinct fixture session")
        parent = await call("wait_for_session", {"session_id": uploaded, "timeout_seconds": 20})
        if not parent["completed"]:
            raise ValueError("uploaded fixture did not complete")
        settings = await call("get_analysis_settings", {})
        await call("set_analysis_settings", {"payload": not settings["payload"]})
        changed = await call("get_analysis_settings", {})
        if changed["payload"] == settings["payload"] or changed["maxTCPBytes"] != settings["maxTCPBytes"]:
            raise ValueError("analysis settings patch lost the new value or changed an omitted budget")
        await call("set_analysis_settings", {"payload": settings["payload"]})
        features = (await call("get_features", {}))["features"]
        enabled = next(f["enabled"] for f in features if f["name"] == "evidence-links")
        await call("set_feature", {"name": "evidence-links", "enabled": not enabled})
        features = (await call("get_features", {}))["features"]
        if next(f["enabled"] for f in features if f["name"] == "evidence-links") == enabled:
            raise ValueError("feature toggle did not take effect")
        await call("set_feature", {"name": "evidence-links", "enabled": enabled})
        await call("set_decoder_config", {"includeDecoders": "UDP,Connection", "excludeDecoders": ""})
        await call("set_bpf_config", {"filter": "udp"})
        child = await call("reanalyze_session", {"session_id": uploaded})
        child_id = child["sessionId"]
        if not child_id or child_id in {sid, uploaded}:
            raise ValueError("reanalysis did not create a distinct child")
        inventory = (await call("list_sessions", {}))["sessions"]
        parent_path = next(s["input_file"] for s in inventory if s["session_id"] == uploaded)
        if child.get("parentInputFile") != parent_path:
            raise ValueError("reanalysis lineage does not identify the uploaded parent")
        finished = await call("wait_for_session", {"session_id": child_id, "timeout_seconds": 20})
        if not finished["completed"]:
            raise ValueError("child did not complete")
        child_config = (await call("get_capture_evidence", {"session_id": child_id}))["config"]
        if child_config["bpf"] != "udp" or set(child_config["includeDecoders"].split(",")) != {"UDP", "Connection"}:
            raise ValueError("child capture manifest lost the selected BPF or decoder settings")
        for session_id in (uploaded, child_id):
            counted = await call("query_audit_records", query | {"session_id": session_id, "count_only": True})
            if counted["summary"]["total"] != 18:
                raise ValueError("reanalysis lost fixture records")
        await call("delete_session", {"session_id": uploaded})
        remaining = {s["session_id"] for s in (await call("list_sessions", {}))["sessions"]}
        if uploaded in remaining or sid not in remaining:
            raise ValueError("upload deletion affected the wrong session")

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
