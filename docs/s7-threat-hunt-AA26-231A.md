# Threat Hunt: Siemens S7 Series PLCs (CISA Joint Advisory AA26-231A)

This document maps netcap's capabilities to the S7 PLC threat hunt described in
CISA Joint Cybersecurity Advisory **AA26-231A** ("Defending Against an Active
Threat to Siemens S7 Series PLCs", 19 Aug 2026) and the associated public
threat-hunt plan.

The campaign is a **hunting problem, not a patching problem**: there is no CVE.
Adversaries use legitimate tooling (snap7 / python-snap7) over the legitimate
S7comm protocol on TCP/102, frequently reaching controllers with default or
absent credentials. Nothing trips a signature. **Read access is the campaign** —
they are mapping process, logic and controllers to pre-position for later write
operations. The window to find them is while they are still reading.

netcap contributes on the **network-visibility** side: it parses S7comm at the
function-code level and turns it into structured audit records that the rule
engine and downstream analytics can hunt over.

---

## Inventory-gate before you hunt

Open every hunt by confirming there is anything to hunt. Process a capture and
check whether any `S7Comm` (or other ICS) records are produced:

```bash
# Decode a capture, including S7comm and Connection records
net capture -read plant.pcap -include S7Comm,Connection -out out/

# Are there any S7comm records at all?
net dump -read out/S7Comm.ncap.gz -fields | head
```

If no S7comm/Modbus/other ICS records are produced, that is a **documented,
defensible negative**, not a wasted hunt. Write it down.

---

## The four hypotheses

The hunt plan orders four hypotheses; the order matters because the first scopes
the rest.

### H1 — Are we visible? (external exposure)

Query Shodan, Censys, Netlas for TCP/102 against your own address space, ASNs
and certificates — **passively, reading the indices, never probing a
controller**.

**netcap scope:** This step is **out of scope for netcap** — netcap is a passive
on-wire traffic tool and does not query third-party scan indices. Use netcap for
the complementary question "is S7comm actually crossing a boundary on my wire?":

- Port-based external exposure: `ICS S7comm External Connection`
  (`rules/examples/industrial_ports.yml`) fires on `DstPort == 102 &&
  IsPublicIP(DstIP)`.
- GeoIP-enriched triage: `S7comm External Connection With GeoIP`
  (`rules/examples/s7comm_hunt.yml`) fires on a public src/dst and attaches
  `SrcGeoLocation`/`DstGeoLocation`/`SrcASN`/`DstASN` (requires the geolocation
  resolver).

> **Gap to write down:** netcap cannot tell you whether a controller is indexed
> in Shodan/Censys. If you have been in a published scan index for months, you
> have been on a target list for months, and netcap will not show that.

### H2 — Is someone enumerating from inside?

The shape: **one source touching many distinct controllers on TCP/102, once
each.** Repeated, frequent pairs are your operational baseline, not a finding.

**netcap:** the rule engine supports **source→distinct-destination cardinality**:

```yaml
- name: S7comm Horizontal Enumeration
  type: Connection
  expression: DstPort == "102" && !IsApprovedWorkstation(SrcIP)
  distinct_field: DstIP
  distinct_threshold: 5
  threshold_window: 300
```

This fires when one source contacts 5+ distinct destinations on TCP/102 within
300 seconds. Tune `distinct_threshold`/`threshold_window` to sit above your
baseline.

### H3 — Is there masqueraded tooling?

snap7 loaded on a host that is not an approved engineering workstation; a Python
process talking to TCP/102; something called `monitor`/`telemetry`/`collector`/
`watchdog` speaking S7comm.

**netcap scope:** netcap sees the **network**, not host processes. It **cannot**
observe "snap7 imported" or "a Python process." What it can do:

- Identify **which host** is speaking S7comm and flag it when the source is not
  an approved engineering workstation (see the approved-workstation baseline
  below). Any S7comm from a non-approved source is a lead for host-side triage.
- Surface the DPI application label (`S7COMM`, `S7COMM_PLUS`) on `Connection`
  records via nDPI (`rules/examples/application_detections.yml`).

> **Gap to write down:** the snap7/Python/process-name discriminators require
> host telemetry (EDR/endpoint), not netcap. netcap narrows the host set; it
> does not confirm the tool.

### H4 — Has anything been written?

This is where it stops being reconnaissance. Function codes outside the read
set, and — critically — **check the acknowledgement**: a job issued is an
attempt; a job acknowledged with **error class `0x00`** is a completed
operation.

netcap parses all of these at the function-code level into `S7Comm` records.
The shipped rules (`rules/examples/s7comm_hunt.yml`):

| Rule | Function code(s) | Meaning |
|---|---|---|
| S7comm Write Operation | `0x05` WriteVar | Process manipulation / pre-positioning |
| S7comm Logic Download | `0x1A–0x1C` | Ladder-logic injection / reprogramming |
| S7comm Logic Theft (Upload) | `0x1D–0x1F` | Logic exfiltration |
| S7comm PLC Stop | `0x29` | Controller halt / denial of control |
| S7comm CPU State Change | `0x28` PI service | Cold/warm/hot restart |
| S7comm Critical Operation Completed | `MessageType == 3 && ErrorClass == 0` | **Acknowledged success**, not just attempted |
| S7comm Read From Non-Approved Source | `0x04` ReadVar | Reconnaissance of PLC memory |
| S7comm Configuration Enumeration (SZL) | UserData CPU/ReadSZL | CPU/firmware/config fingerprinting |

The decoder also flags `IsCriticalOperation` and `IsSecurityRelevant` on the
record, and names cold/warm/hot restart in `SubFunctionName`.

---

## The two things that decide almost every call

### 1. Build the approved-workstation baseline, and negate it

Almost every discriminator reduces to a single question: **does an authorization
record exist for this source?** An uncorrelated write, download, upload or
CPU-state change is escalated **regardless of how legitimate the source looks** —
third-party integrators and managed service providers are explicitly in scope.

netcap wires this in as a first-class rule helper. Provide the approved
engineering-workstation IPs in a file (bare IP per line, or `name,ip` CSV):

```bash
net capture -read plant.pcap -include S7Comm,Connection \
  -rules rules/examples/s7comm_hunt.yml \
  -approved-workstations approved-ews.txt \
  -out out/
```

Then every hunt rule negates the set with `!IsApprovedWorkstation(SrcIP)`.

> **Do not allowlist by hostname pattern inside the query.** If a compromised
> approved workstation is your problem, a pattern match hides it. The baseline is
> built out-of-band (the file) and negated in the rule.

### 2. Go find the paperwork

An alert from these rules is a pointer to a question — *is there a change record,
a maintenance window, an authorized integrator session for this?* An uncorrelated
finding gets escalated. Use the `S7comm Off-Hours Operation` rule
(`!IsBusinessHours(Timestamp, 8, 18)`) to pre-filter activity outside the change
window.

---

## Say what you couldn't see (named gaps)

The most damaging outcome of an OT hunt is a clean-looking negative that quietly
covered half the estate. Name the gaps:

- **S7CommPlus payloads are integrity-obscured.** S7-1200/1500 controllers
  programmed through TIA Portal speak S7CommPlus (protocol id `0x72`), whose
  body is protected by session-keyed integrity material. netcap parses the
  cleartext framing (opcode: Request/Response/Notification) and **explicitly
  sets `PayloadObscured = true`**, plus fires `S7CommPlus Obscured Payload`. You
  can prove a connection happened; you often cannot prove which function code it
  carried. Corroborate with the approved-workstation baseline out-of-band.
- **No full-payload capture on TCP/102 → no function-code analysis.** Segments
  where only headers/flows are captured support H1/H2 (exposure, fan-out) but
  **not** H4 (writes/downloads). Confirm your capture has S7comm payloads.
- **Off-network reconnaissance is invisible.** Target selection via Shodan/
  Censys/ZoomEye never touches your wire (H1). netcap cannot see it.
- **Host-side masquerading (snap7/Python/process names) needs endpoint
  telemetry** (H3). netcap narrows the host set but does not confirm the tool.
- **GeoIP requires the resolver and databases.** Country/ASN on `Connection`
  records is empty when the geolocation resolver is disabled or the address is
  private/unresolved.
- **Threshold/cardinality windows use the record timestamp** (fixed for offline
  replay). Ensure capture timestamps are accurate.

---

## Output and downstream hunting

`S7Comm`, `Connection` and `Alert` are all first-class audit records and flow
through the standard writers:

- **Protobuf** (default), **CSV**, **JSON** for offline analysis.
- **Elasticsearch** (`net export ... ` / `io/elastic.go`) for Kibana dashboards
  and geographic maps.
- **Alerts** are written to `Alert.ncap.gz` and carry the matched record,
  MITRE IDs, severity and rule expression for triage.

## Field reference (S7Comm record)

Key fields for hunting (see `netcap.proto` `message S7Comm`):

- `FunctionCode` / `FunctionName` — the operation (`0x04` read, `0x05` write, …).
- `MessageType` / `MessageTypeName` — Job (1), Ack (2), Ack-Data (3), UserData (7).
- `ErrorClass` / `ErrorCode` / `ErrorName` — `ErrorClass == 0` on an Ack-Data
  means the operation completed.
- `IsCriticalOperation` / `IsSecurityRelevant` — decoder-computed flags.
- `SubFunctionName` — names cold/warm/hot restart for PI services.
- `UserDataFunctionGroup` / `UserDataSubFunction` — SZL / CPU function
  enumeration.
- `PayloadObscured`, `S7PlusOpcode`, `S7PlusOpcodeName` — S7CommPlus visibility.

## MITRE ATT&CK for ICS mapping

T0846 (Remote System Discovery), T0888 (Remote System Information Discovery),
T0893 (Data from Local System), T0821 (Modify Controller Tasking), T0843
(Program Download), T0845 (Program Upload/logic theft), T0813/T0816 (Denial of
Control / Device Restart-Shutdown), T0885/T0868 (external exposure), plus the
enterprise techniques from the advisory: T1587.004, T1588.007, T1596.005,
T1694, T0834, T0849.
