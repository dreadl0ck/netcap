# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==1.26.0", "jsonschema==4.26.0"]
# ///

import argparse
import asyncio
import base64
import hashlib
import io
import json
import zipfile
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
list_offline_evaluations list_certificates get_stream_evidence
""".split()


async def check(binary, capture, http_capture, data_dir):
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
        dhcp_args = {"fingerprint": "1,3,6,15", "vendor": "fixture"}
        dhcp = await call("lookup_dhcp_fingerprint", dhcp_args)
        if (dhcp.get("disabled") is not True or not dhcp.get("note")
                or any(dhcp.get(key) != value for key, value in dhcp_args.items())):
            raise ValueError("DHCP lookup lost its disabled qualification or input identity")
        service = await call("resolve", {"kind": "iana_service", "value": " 5353 ", "protocol": "udp"})
        if ((service.get("kind"), service.get("value"), service.get("protocol"), service.get("port"))
                != ("iana_service", "5353", "udp", 5353) or not isinstance(service.get("service"), str)):
            raise ValueError("local service lookup lost its normalized selector or result")
        firewall = {
            "bundle": json.dumps({"version": "1", "id": "fixture", "mode": "enforce", "default": "deny",
                                  "rules": [{"id": "get", "expression": "Method == 'GET'", "action": "allow"}]}),
            "events": [{"method": method, "protocol": "http"} for method in ("GET", "POST")],
        }
        policy = (await call("evaluate_firewall_policy", firewall))["report"]
        repeated = (await call("evaluate_firewall_policy", firewall))["report"]
        if (policy["effects_dispatched"] is not False or repeated["effects_dispatched"] is not False
                or not policy["revision"] or policy["revision"] != repeated["revision"]
                or any([d["verdict"] for d in result["decisions"]] != ["allow", "deny"]
                       for result in (policy, repeated))):
            raise ValueError("offline firewall replay lost stable policy identity, ordered verdicts or effect isolation")
        streams = (await call("get_stream_evidence", args))["data"]
        stream, direction = next(
            (row, side) for row in streams for side in ("client", "server")
            if int(row["manifest"][side]["length"]) > 1
        )
        expected = stream["manifest"][direction]
        limit = min(64, int(expected["length"]) - 1)
        target = args | {"id": stream["id"], "direction": direction, "limit": limit, "spanLimit": 1}
        body = bytearray()
        manifest_hash = None
        while True:
            page = await call("get_stream_content", target | {"offset": len(body)} | (
                {"manifestSHA256": manifest_hash} if manifest_hash else {}))
            if manifest_hash is None:
                manifest_hash = page["manifestSHA256"]
            chunk = base64.b64decode(page["data"], validate=True)
            if (page["manifestSHA256"] != manifest_hash or page["offset"] != len(body)
                    or int(page["totalBytes"]) != int(expected["length"])
                    or not 0 < len(chunk) <= limit or len(page["spans"]) > 1
                    or len(body) + len(chunk) > int(expected["length"])):
                raise ValueError("invalid directional evidence page")
            body.extend(chunk)
            if not page["hasMore"]:
                break
        if len(body) != int(expected["length"]) or hashlib.sha256(body).hexdigest() != expected["sha256"]:
            raise ValueError("directional evidence differs from its manifest")
        exact = await call("get_stream_evidence", args | {"id": stream["id"], "direction": "manifest"})
        if (exact[direction] != expected or len(exact["spans"]) != stream["spanCount"]
                or exact["connectionKey"] != stream["manifest"]["connectionKey"]):
            raise ValueError("exact manifest disagrees with the inventory or directional read")
        for offset in (len(body), len(body) + 1):
            end = await call("get_stream_content", target | {"offset": offset, "manifestSHA256": manifest_hash})
            if (end["data"] != "" or end["hasMore"] or end["offset"] != offset
                    or int(end["totalBytes"]) != len(body) or end["manifestSHA256"] != manifest_hash):
                raise ValueError("terminal directional page lost its empty data or verified identity")
        for continuation in ({"offset": 1}, {"spanOffset": 1}):
            unbound = await client.call_tool("get_stream_content", target | continuation)
            if not unbound.isError:
                raise ValueError(f"unbound directional continuation accepted: {continuation}")
        spans = await call("get_stream_content", target | {"spanOffset": 1, "manifestSHA256": manifest_hash})
        if spans["spanOffset"] != 1 or spans["manifestSHA256"] != manifest_hash or len(spans["spans"]) > 1:
            raise ValueError("span continuation lost its offset, identity or bound")
        stale_stream = await client.call_tool("get_stream_content", target | {"offset": 1, "manifestSHA256": "0" * 64})
        if not stale_stream.isError:
            raise ValueError("changed stream manifest digest accepted")
        feature_states = (await call("get_features", {}))["features"]
        link_enabled = next(f["enabled"] for f in feature_states if f["name"] == "evidence-links")
        await call("set_feature", {"name": "evidence-links", "enabled": True})
        related = await call("get_related_evidence", args | {"type": "Connection", "ordinal": 0})
        if related["target"]["type"] != "Connection" or related["target"]["ordinal"] != 0:
            raise ValueError("related evidence changed the requested target")
        await call("set_feature", {"name": "evidence-links", "enabled": link_enabled})
        pack = """format: netcap-offline-rules/v1
rules:
  - id: udp-fixture
    name: UDP fixture
    type: UDP
    expression: 'DstPort == 5353'
    severity: low
    enabled: true
    threshold:
      count: 2
      window: 600s
      group_by: [DstPort]
"""
        await call("validate_offline_rule_pack", {"yaml": pack})
        invalid = await client.call_tool("validate_offline_rule_pack", {"yaml": pack + "---\n{}\n"})
        if not invalid.isError:
            raise ValueError("multiple offline rule documents accepted")
        report = (await call("execute_offline_rule_pack", args | {"yaml": pack}))["report"]
        history = (await call("list_offline_evaluations", args))["evaluations"]
        udp_stats, = report["types"]
        if (report["status"] != "partial" or int(report["committedAlerts"]) != 0
                or udp_stats["type"] != "UDP" or int(udp_stats["records"]) != 18
                or int(udp_stats["unknownScopes"]) != 18):
            raise ValueError("unscoped UDP fixture lost its partial evaluation qualification")
        if not any(saved["id"] == report["id"] and saved["packDigest"] == report["packDigest"] for saved in history):
            raise ValueError("offline evaluation report was not retained")
        manual = await call("execute_detection_rules", args)
        results = manual["ruleResults"]
        successful = [row for row in results if row["success"]]
        if (not results or manual["success"] != (len(successful) == len(results))
                or manual["totalRecords"] != sum(row["recordsRead"] for row in successful)
                or manual["totalAlerts"] != sum(row["alertsCount"] for row in successful)):
            raise ValueError("manual rule replay lost per-rule outcomes or aggregate totals")
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
        asset = await call("get_asset_context", args | {"asset": endpoint})
        if asset["asset"] != endpoint or not asset["records"] or asset["totalRecords"] < len(asset["records"]):
            raise ValueError("asset context lost the observed endpoint or its records")
        row = connections["records"][0]
        tuple_args = {"src_ip": endpoint, "src_port": str(row["SrcPort"]),
                      "dst_ip": row["DstIP"], "dst_port": str(row["DstPort"]), "protocol": "UDP"}
        conversation = args | tuple_args
        first = await call("get_conversation", conversation | {"limit": 16})
        second = await call("get_conversation", conversation | {"limit": 16, "offset": 16})
        combined = await call("get_conversation", conversation | {"limit": 32})
        chunks = [base64.b64decode(p["conversationData"], validate=True) for p in (first, second, combined)]
        if (not all(p["exists"] and p["protocol"] == "UDP" for p in (first, second, combined))
                or first["offset"] != 0 or second["offset"] != 16 or not first["hasMore"]
                or first["totalSize"] != second["totalSize"] or [len(c) for c in chunks] != [16, 16, 32]
                or chunks[0] + chunks[1] != chunks[2]):
            raise ValueError("UDP conversation pages lost byte bounds or continuity")
        for name, selector in (
            ("carve_subpcap_for_host", {"host": endpoint, "run_id": binding["runId"]}),
            ("carve_subpcap_for_connection", tuple_args | {"run_id": binding["runId"]}),
            ("export_packet_evidence", {"runId": binding["runId"], "sourceSHA256": binding["sourceSHA256"], "bpf": "udp", "maxPackets": 18}),
        ):
            carved = await call(name, args | selector)
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
            if name == "export_packet_evidence":
                with zipfile.ZipFile(io.BytesIO(wire)) as bundle:
                    manifest = json.loads(bundle.read("manifest.json"))
                    packets = bundle.read("packets.pcapng")
                if (manifest["sourceSHA256"] != binding["sourceSHA256"] or manifest["selectedPackets"] != 18
                        or hashlib.sha256(packets).hexdigest() != manifest["outputSHA256"]):
                    raise ValueError("packet export provenance did not match the fixture")
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
            ("get_chart_data", args | {"type": "UDP", "field": "Length", "max_data_points": 5}),
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
                if name == "get_chart_data":
                    if result["type"] != "UDP" or result["field"] != "Length" or not 1 <= len(result["data"]) <= 5:
                        raise ValueError("UDP chart lost its field or point bound")
            except Exception as exc:
                failures.append(f"{name}: {exc}")

        query = args | {"type": "UDP"}
        first = await call("query_audit_records", query | {"allow_partial": True, "limit": 1})
        summary = first["summary"]
        second = await call("query_audit_records", query | {
            "allow_partial": True, "limit": 17, "offset": 1,
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
        sealed_count = await call("query_audit_records", query | {"allow_partial": True, "count_only": True})
        counted = sealed_count["summary"]
        if ("records" in sealed_count or counted["total"] != 18 or not counted["partialAdmission"]
                or counted["runId"] != summary["runId"] or counted["stageGeneration"] != summary["stageGeneration"]
                or not counted["queryGeneration"] or counted["queryGeneration"] == summary["queryGeneration"]):
            raise ValueError("sealed count-only query lost coverage or used the record query generation")
        full = await call("query_audit_records", query | {"limit": 18})
        if (not summary["partialAdmission"] or len(first["records"]) != 1 or len(second["records"]) != 17
                or second["summary"]["queryGeneration"] != summary["queryGeneration"]
                or first["records"] + second["records"] != full["records"]
                or count["summary"]["total"] != 18 or "records" in count):
            raise ValueError("fixture query count or sealed continuation differs")
        empty = await call("query_audit_records", query | {"offset": 18})
        if empty["records"] != []:
            raise ValueError("empty page did not return an array")

        http_session = (await call("ingest_pcap", {"path": str(http_capture)}))["session_id"]
        if not http_session or http_session == sid:
            raise ValueError("HTTP ingest did not create a distinct session")
        http_args = {"session_id": http_session}
        if not (await call("wait_for_session", http_args | {"timeout_seconds": 20}))["completed"]:
            raise ValueError("HTTP fixture did not complete")
        hosts = await call("list_hosts", http_args)
        total = hosts["totalCount"]
        generation = hosts["generation"]
        if not generation or not 2 <= total <= 100 or len(hosts["hosts"]) != total:
            raise ValueError("HTTP fixture did not produce a complete, multi-host inventory")
        paged_hosts = []
        for offset in range(total + 1):
            page = await call("list_hosts", http_args | {"limit": 1, "offset": offset, "generation": generation})
            if (page["generation"] != generation or page["totalCount"] != total
                    or page["offset"] != offset or page["limit"] != 1
                    or page["hosts"] != hosts["hosts"][offset:offset + 1]
                    or page["next_offset"] != min(offset + 1, total)
                    or page["has_more"] != (offset + 1 < total)):
                raise ValueError("host continuation does not match the inventory")
            paged_hosts.extend(page["hosts"])
        if paged_hosts != hosts["hosts"]:
            raise ValueError("host continuation lost or duplicated rows")
        stale_hosts = await client.call_tool("list_hosts", http_args | {"limit": 1, "offset": 1, "generation": "0" * 64})
        if not stale_hosts.isError:
            raise ValueError("host continuation accepted a stale generation")
        inventory = await call("list_extracted_files", http_args)
        row = next((row for row in inventory["files"] if 1 < row["size"] <= 16384 and row.get("sha256")), None)
        if row is None:
            raise ValueError("HTTP fixture did not produce a bounded, hashed extracted file")
        target = http_args | {"file_path": row["path"]}
        contents = bytearray()
        split = min(8, row["size"] - 1)
        for offset, limit in ((0, split), (split, row["size"] - split), (row["size"], 8)):
            page = await call("get_extracted_file_content", target | {"offset": offset, "limit": limit})
            chunk = bytes.fromhex(page["data"])
            if (page["encoding"] != "hex" or page["offset"] != offset or page["totalSize"] != row["size"]
                    or page["session_id"] != http_session or page["file_path"] != row["path"]
                    or len(chunk) != min(limit, row["size"] - offset)
                    or page["hasMore"] != (offset + len(chunk) < row["size"])):
                raise ValueError("extracted file page lost its bounds or EOF state")
            contents.extend(chunk)
        if hashlib.sha256(contents).hexdigest() != row["sha256"]:
            raise ValueError("extracted file pages do not match inventory digest")
        iocs = await call("extract_iocs_from_file", target | {"kinds": "domain", "max_per_kind": 1})
        exif = await call("get_image_exif", target)
        if any(result["session_id"] != http_session or result["file_path"] != row["path"]
               for result in (iocs, exif)):
            raise ValueError("file analysis lost artifact identity")
        if iocs["size_scanned"] != len(contents) or iocs["kinds"] != ["domain"] or len(iocs["domains"]) > 1:
            raise ValueError("IOC extraction lost its scan size or requested bounds")
        if exif["entries"] != [] or not exif.get("note"):
            raise ValueError("file without EXIF did not return a qualified empty result")
        await call("delete_session", http_args)

        schema = Path(data_dir).resolve() / "contract.proto"
        valid_schema = 'syntax = "proto3"; package contract; message Sample { string label = 1; }\n'
        schema.write_text(valid_schema, encoding="utf-8")
        await call("add_protobuf_search_path", {"path": str(schema)})
        await call("recompile_protobuf_schemas", {})
        messages = (await call("list_protobuf_messages", {}))["messages"]
        if {message["fullName"] for message in messages} != {"contract.Sample"}:
            raise ValueError("schema recompilation did not retain the fixture message")
        schema.write_text('syntax = "proto3"; message Incomplete {', encoding="utf-8")
        failed = await client.call_tool("recompile_protobuf_schemas", {})
        if not failed.isError:
            raise ValueError("invalid schema recompilation reported success")
        invalid_status = await call("get_protobuf_status", {})
        retained = (await call("list_protobuf_messages", {}))["messages"]
        if not invalid_status["loaded"] or not invalid_status["errors"] or retained != messages:
            raise ValueError("invalid reload lost its diagnostic or replaced the active schema")
        schema.write_text(valid_schema, encoding="utf-8")
        await call("recompile_protobuf_schemas", {})
        await call("set_protobuf_mapping", {"port": 49001, "messageType": "contract.Sample"})
        proto = await call("get_protobuf_status", {})
        if (not proto["loaded"] or proto["errors"] or proto["fileCount"] != 1
                or proto["portMappings"] != [{"port": 49001, "messageType": "contract.Sample"}]):
            raise ValueError("protobuf status lost the compiled schema or explicit port mapping")

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

        for show_alternatives in (True, False):
            await call("configure_protobuf", {"operation": "preferences", "showAlternatives": show_alternatives})
            status = await call("get_protobuf_status", {})
            if status["showAlternatives"] is not show_alternatives or status["portMappings"] != proto["portMappings"]:
                raise ValueError("protobuf preference did not round-trip or changed the existing mapping")
        await call("configure_protobuf", {"operation": "unmap-port", "port": 49001})
        status = await call("get_protobuf_status", {})
        if status["portMappings"] != [] or status["messageCount"] != 1:
            raise ValueError("unmapping did not clear only the port mapping")
        await call("configure_protobuf", {"operation": "remove-path", "path": str(schema)})
        status = await call("get_protobuf_status", {})
        if status["searchPaths"] != [] or (await call("list_protobuf_messages", {}))["messages"] != []:
            raise ValueError("schema removal did not clear the fixture registry")

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
    parser = argparse.ArgumentParser(description="Check Netcap's stdio tool contracts on the mDNS and HTTP fixtures.")
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    with TemporaryDirectory(prefix="netcap-mcp-contracts-") as data_dir:
        passed = asyncio.run(check(args.binary.resolve(), repo / "internal/collector/testdata/voip/mdns.pcap",
                                   repo / "testdata/recheck-v0168/base_http.pcap", data_dir))
        raise SystemExit(0 if passed else 1)
