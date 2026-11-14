# Siemens S7 threat hunting

This page maps Netcap to the S7 PLC hunt in CISA Joint Cybersecurity Advisory **AA26-231A** ("Defending Against an Active Threat to Siemens S7 Series PLCs", 19 Aug 2026) and its public threat-hunt plan.

There is no CVE to patch. The attackers use legitimate tooling (snap7 / python-snap7) over S7comm on TCP/102, often against controllers with default or no credentials. Reading is the campaign: they map the process, logic and controllers before they write. Your window is while they are still reading.

Netcap covers the network side. It parses S7comm at the function-code level into audit records that the rule engine and your analytics can query.

A typical case: `plant.pcap` comes from the mirror port of a plant switch. Siemens PLCs sit at 10.10.1.11 to 10.10.1.15, and the only approved engineering workstation is 10.10.1.50. You look for any other host speaking S7comm, one host reading many PLCs, and any CPU stop or block download.

***

## Inventory-gate before you hunt

Start by checking that the capture contains anything to hunt:

```bash
# Decode a capture, including S7comm and Connection records
net capture -read plant.pcap -include S7Comm,Connection -out out/

# Are there any S7comm records at all?
net dump -read out/S7Comm.ncap.gz -fields
net dump -read out/S7Comm.ncap.gz -json
```

`-fields` shows the schema, not whether the file has records. If no ICS records come out, report that no supported ICS records were decoded from this input, and check the observation point, enabled decoders, capture loss, truncation and encryption before you rely on that.

***

## The four hypotheses

The hunt plan orders four hypotheses. The first one scopes the rest.

### H1 — Are we visible? (external exposure)

Query Shodan, Censys and Netlas for TCP/102 against your own address space, ASNs and certificates. Read the indices only; never probe a controller.

Netcap does not query scan indices, so it cannot tell you whether a controller is indexed. It can tell you whether S7comm actually crosses a boundary on your wire:

* `ICS S7comm External Connection` (`internal/rules/examples/industrial_ports.yml`) fires on `DstPort == 102 && IsPublicIP(DstIP)`.
* `S7comm External Connection With GeoIP` (`internal/rules/examples/s7comm_hunt.yml`) fires on a public source or destination and attaches `SrcGeoLocation`, `DstGeoLocation`, `SrcASN` and `DstASN`. It needs the geolocation resolver.

### H2 — Is someone enumerating from inside?

Look for one source touching many distinct controllers on TCP/102, once each. Pairs that talk repeatedly are your operational baseline.

The rule engine supports source-to-distinct-destination cardinality:

```yaml
rules:
  - name: S7comm Horizontal Enumeration
    description: One unapproved source contacted five distinct TCP/102 destinations
    type: Connection
    expression: DstPort == "102" && !IsApprovedWorkstation(SrcIP)
    distinct_field: DstIP
    distinct_threshold: 5
    threshold_window: 300
    severity: medium
    enabled: true
```

This fires when one source contacts 5 or more distinct destinations on TCP/102 within 300 seconds. Set `distinct_threshold` and `threshold_window` above your baseline.

### H3 — Is there masqueraded tooling?

Typical signs are snap7 on a host that is not an approved engineering workstation, a Python process talking to TCP/102, or something named `monitor`, `telemetry`, `collector` or `watchdog` speaking S7comm.

Netcap sees the network, not host processes, so it cannot see "snap7 imported" or "a Python process". It can:

* Show which host speaks S7comm and flag sources that are not approved engineering workstations (see the baseline below). S7comm from any other source is a lead for host-side triage.
* Add the nDPI application label (`S7COMM`, `S7COMM_PLUS`) to `Connection` records (`internal/rules/examples/application_detections.yml`).

Confirming the tool needs endpoint (EDR) telemetry. Netcap narrows the list of hosts to check.

### H4 — Has anything been written?

Separate the request, the response header, the item results and the process effect. `MessageType == 3 && ErrorClass == 0 && ErrorCode == 0` identifies an Ack-Data with no header error. It does not mean every item succeeded or that the process changed.

Check `DataItems[].ReturnCode` (`255` means the item succeeded) and match the request and PDU reference. The item parser does not cover every response shape, so an empty item list is not a success. Confirm operational effects with controller or process evidence.

The shipped rules (`internal/rules/examples/s7comm_hunt.yml`) cover these function codes:

| Rule                                     | Function code(s)                                        | Meaning                                                |
| ---------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------ |
| S7comm Write Operation                   | `0x05` WriteVar                                         | Process manipulation, pre-positioning                  |
| S7comm Logic Download                    | `0x1A–0x1C`                                             | Ladder-logic injection, reprogramming                  |
| S7comm Logic Theft (Upload)              | `0x1D–0x1F`                                             | Logic exfiltration                                     |
| S7comm PLC Stop                          | `0x29`                                                  | Controller halt, denial of control                     |
| S7comm CPU State Change                  | `0x28` PI service                                       | Cold, warm or hot restart                              |
| S7comm Critical Operation Acknowledgment | `MessageType == 3 && ErrorClass == 0 && ErrorCode == 0` | Header result only. Check item results and the request |
| S7comm Read From Non-Approved Source     | `0x04` ReadVar                                          | Reconnaissance of PLC memory                           |
| S7comm Configuration Enumeration (SZL)   | UserData CPU/ReadSZL                                    | CPU, firmware and configuration fingerprinting         |

The decoder also sets `IsCriticalOperation` and `IsSecurityRelevant` on the record and names cold, warm and hot restart in `SubFunctionName`.

***

## The two things that decide almost every call

### 1. Build the approved-workstation baseline, and negate it

Almost every check comes down to one question: does an authorization record exist for this source? Escalate any write, download, upload or CPU-state change without one, however legitimate the source looks. That includes third-party integrators and managed service providers.

Give Netcap the approved engineering-workstation IPs in a file (one IP per line, or `name,ip` CSV):

```bash
net capture -read plant.pcap -include S7Comm,Connection \
  -rules internal/rules/examples/s7comm_hunt.yml \
  -approved-workstations approved-ews.txt \
  -out out/
```

Request records carry the initiator in `SrcIP`, and response records carry it in `DstIP`. Negate the approved set on the matching endpoint. The `S7comm Critical Operation Acknowledgment` rule negates it on `DstIP`. The request rules require `MessageType == 1`. The S7CommPlus visibility rule reports both directions and does not check the initiator.

Do not allowlist by hostname pattern inside the query: if an approved workstation is compromised, a pattern match hides it. Build the baseline outside the query, in the file, and negate it in the rule.

**Service mode:** with `net capture --service`, the webui/service process evaluates rules over the written audit records. Give that process the allowlist through the `NC_APPROVED_WORKSTATIONS` environment variable (or the `-approved-workstations` flag):

```bash
NC_APPROVED_WORKSTATIONS=approved-ews.txt net capture --service -http 127.0.0.1:8080
```

If the allowlist is not loaded, `IsApprovedWorkstation` returns false for every source, so every negated rule fires on all S7comm traffic, including your own engineering workstations.

### 2. Go find the paperwork

An alert is a question: is there a change record, a maintenance window or an authorized integrator session for this? Escalate anything without one. The `S7comm Off-Hours Operation` rule (`!IsBusinessHours(Timestamp, 8, 18)`) pre-filters activity outside the change window.

***

## Say what you couldn't see (named gaps)

An empty result that quietly missed half the estate is the worst outcome of an OT hunt. Write down what you could not see:

* **S7CommPlus payloads are obscured.** S7-1200/1500 controllers programmed through TIA Portal speak S7CommPlus (protocol ID `0x72`), whose body is protected by session-keyed integrity material. Netcap parses the cleartext framing (opcode: Request, Response, Notification), sets `PayloadObscured = true` and fires `S7CommPlus Obscured Payload`. You can show that a connection happened, but often not which function code it carried. Use the approved-workstation baseline to judge it.
* **Headers-only capture on TCP/102.** Without payloads there is no function-code analysis. Flow data supports H1 and H2 (exposure, fan-out) but not H4 (writes and downloads). Confirm your capture includes S7comm payloads.
* **Off-network reconnaissance.** Target selection through Shodan, Censys or ZoomEye never touches your wire (H1).
* **Host-side masquerading** (snap7, Python, process names) needs endpoint telemetry (H3).
* **GeoIP** needs the resolver and its databases. Country and ASN on `Connection` records are empty when the resolver is off or the address is private or unresolved.
* **Cardinality windows** use the record timestamp, so capture timestamps must be accurate.

***

## Output and downstream hunting

`S7Comm`, `Connection` and `Alert` records go through the standard writers:

* Protobuf (default), CSV and JSON for offline analysis.
* Elasticsearch has its own writer. `net export` is the Prometheus exporter, not an Elasticsearch export.
* Alerts are written to `Alert.ncap.gz` with the matched record, MITRE IDs, severity and rule expression.

## Field reference (S7Comm record)

Key fields for hunting (see `message S7Comm` in `types/netcap.proto`):

* `FunctionCode` / `FunctionName`: the operation (`0x04` read, `0x05` write, and so on).
* `MessageType` / `MessageTypeName`: Job (1), Ack (2), Ack-Data (3), UserData (7).
* `ErrorClass` / `ErrorCode` / `ErrorName`: header-level errors. Zero does not tell you whether items succeeded or the process changed.
* `IsCriticalOperation` / `IsSecurityRelevant`: flags computed by the decoder.
* `SubFunctionName`: names cold, warm and hot restart for PI services.
* `UserDataFunctionGroup` / `UserDataSubFunction`: SZL and CPU function enumeration.
* `PayloadObscured`, `S7PlusOpcode`, `S7PlusOpcodeName`: S7CommPlus visibility.

## MITRE ATT\&CK for ICS mapping

T0846 (Remote System Discovery), T0888 (Remote System Information Discovery), T0893 (Data from Local System), T0821 (Modify Controller Tasking), T0843 (Program Download), T0845 (Program Upload/logic theft), T0813/T0816 (Denial of Control / Device Restart-Shutdown), T0885/T0868 (external exposure), plus the enterprise techniques from the advisory: T1587.004, T1588.007, T1596.005, T1694, T0834, T0849.
