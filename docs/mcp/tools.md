# Netcap MCP tool reference

<!--- DO NOT EDIT — regenerate with: go test ./internal/mcp/ -run TestToolDocsUpToDate -update -->

This catalogue is generated from the live tool registry in
`internal/mcp/`. Every entry corresponds to one `tools/call`
name on the netcap MCP server.

Sessions
--------

A `session_id` may be an opaque analysis ID for an uploaded capture in
either mode, or an absolute filesystem path for a legacy local input. It is
passed as a request selector without changing the globally active capture.
Pass back exactly what
`ingest_pcap` or `list_sessions` returns.

Response limits
---------------

- Every serialized tool result, including text and structured content, is
  capped at 256 KiB. Oversized successful JSON is retained as an artifact
  readable in bounded pages with `read_mcp_artifact`.
- Successful results match an `outputSchema` and include
  `structuredContent`. Object fields remain native; top-level arrays
  and scalars use `data`, and plain text uses `text`.
- `query_audit_records` and the list_* tools support
  `limit` / `offset` server-side.
- Long-running operations (ingest, reanalyze) return immediately and are
  polled via `get_session_info` (look at the `completed`
  field). YARA scans and detection-rule executions are synchronous.

Hints
-----

Each tool exposes the standard MCP hint annotations (read-only,
destructive, idempotent, open-world). Treat them as advisory: a
`destructive` tool should prompt the user before invocation.

## Tool catalogue (119 tools)

Auto-generated from the live tool registry. Do not edit by hand; run `go test ./internal/mcp/ -run TestToolDocsUpToDate -update` to regenerate.

### `add_protobuf_search_path`

Add an absolute dedicated schema directory or regular .proto file and recompile. System roots/symlinks are rejected; sources are snapshotted within 256 files (2 MiB each), 16 MiB total, 10000 entries and 16 levels. This changes the process-wide registry; inspect get_protobuf_status for compile errors.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "path": {
      "description": "Absolute dedicated schema directory or regular .proto file.",
      "type": "string"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

### `alert_delivery`

Durable alert delivery through a named startup-enrolled webhook binding. enqueue requires session_id/run_id and derives stable capture scope; status/deliver use the returned delivery_id so retries survive source expiry and restart. deliver obeys existing network policy. Limits remain within enrollment; pending/rejected notices are explicit errors, and receivers must deduplicate Idempotency-Key. No destination, token, arbitrary payload or outbox path is accepted.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "binding": {
      "type": "string"
    },
    "delivery_id": {
      "type": "string"
    },
    "limit": {
      "type": "integer"
    },
    "operation": {
      "enum": [
        "enqueue",
        "status",
        "deliver"
      ],
      "type": "string"
    },
    "run_id": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "operation",
    "binding"
  ],
  "type": "object"
}
```

### `analyst_workspace`

Load local saved queries/reports when document is absent. Explicit document saves use expectedRevision CAS; new documents must be draft. Review requires unchanged persisted content and explicit reviewer. No automatic approval.

**Arguments (JSON Schema):**

```json
{
  "type": "object",
  "properties": {
    "source": {
      "type": "object",
      "properties": {
        "sessionId": {
          "type": "string"
        },
        "inputFile": {
          "type": "string"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        }
      },
      "required": [
        "binding"
      ],
      "additionalProperties": false
    },
    "document": {
      "type": [
        "null",
        "object"
      ],
      "properties": {
        "catalogueSnapshotSHA256": {
          "type": "string"
        },
        "includedSources": {
          "type": [
            "null",
            "array"
          ],
          "items": {
            "type": "object",
            "properties": {
              "sessionId": {
                "type": "string"
              },
              "inputFile": {
                "type": "string"
              },
              "binding": {
                "type": "object",
                "properties": {
                  "runId": {
                    "type": "string"
                  },
                  "sourceSHA256": {
                    "type": "string"
                  },
                  "manifestSHA256": {
                    "type": "string"
                  }
                },
                "required": [
                  "runId",
                  "sourceSHA256",
                  "manifestSHA256"
                ],
                "additionalProperties": false
              }
            },
            "required": [
              "binding"
            ],
            "additionalProperties": false
          }
        },
        "id": {
          "type": "string"
        },
        "revision": {
          "type": "integer"
        },
        "kind": {
          "type": "string"
        },
        "title": {
          "type": "string"
        },
        "body": {
          "type": "string"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        },
        "query": {
          "type": [
            "null",
            "object"
          ],
          "properties": {
            "kind": {
              "type": "string"
            },
            "value": {
              "type": "string"
            },
            "types": {
              "type": [
                "null",
                "array"
              ],
              "items": {
                "type": "string"
              }
            }
          },
          "required": [
            "kind",
            "value",
            "types"
          ],
          "additionalProperties": false
        },
        "references": {
          "type": [
            "null",
            "array"
          ],
          "items": {
            "type": "object",
            "properties": {
              "version": {
                "type": "integer"
              },
              "binding": {
                "type": "object",
                "properties": {
                  "runId": {
                    "type": "string"
                  },
                  "sourceSHA256": {
                    "type": "string"
                  },
                  "manifestSHA256": {
                    "type": "string"
                  }
                },
                "required": [
                  "runId",
                  "sourceSHA256",
                  "manifestSHA256"
                ],
                "additionalProperties": false
              },
              "type": {
                "type": "string"
              },
              "file": {
                "type": "string"
              },
              "fileSHA256": {
                "type": "string"
              },
              "ordinal": {
                "type": "string"
              },
              "recordSHA256": {
                "type": "string"
              },
              "timestampNs": {
                "type": "string"
              }
            },
            "required": [
              "version",
              "binding",
              "type",
              "file",
              "fileSHA256",
              "ordinal",
              "recordSHA256",
              "timestampNs"
            ],
            "additionalProperties": false
          }
        },
        "review": {
          "type": "string"
        },
        "reviewer": {
          "type": "string"
        },
        "updatedAt": {
          "type": "string"
        }
      },
      "required": [
        "includedSources",
        "id",
        "revision",
        "kind",
        "title",
        "body",
        "binding",
        "references",
        "review",
        "updatedAt"
      ],
      "additionalProperties": false
    },
    "expectedRevision": {
      "type": "integer"
    }
  },
  "required": [
    "source",
    "expectedRevision"
  ],
  "additionalProperties": false
}
```

### `analyze_tls_capture`

Analyze a registered PCAP/TLS stream using an explicitly supplied backend-local NSS keyLog and installed tshark. sourceSHA256 binds the capture; stream (TLS follow index) and communityId are exclusive. Omit both to select the unique decryptable stream; ambiguity requires explicit selection. Input and secrets are privately snapshotted; secret contents/paths are never included in output. Node ordering and completeness remain qualified. Service mode requires its existing administrator identity.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "communityId": {
      "type": "string"
    },
    "keyLog": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "sourceSHA256": {
      "type": "string"
    },
    "stream": {
      "anyOf": [
        {
          "type": "integer"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "keyLog",
    "sourceSHA256"
  ],
  "type": "object"
}
```

### `carve_subpcap_for_certificate`

Produce a sub-PCAP for the TCP flow that carried a given TLS certificate (identified by its 4-tuple).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `dst_port` | string | yes | Destination port. |
| `end_ns` | string |  | Inclusive UTC Unix nanoseconds; supply together with start_ns. |
| `run_id` | string |  | Expected capture generation; stale generations are rejected by the backend. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP of the TLS flow. |
| `src_port` | string | yes | Source port. |
| `start_ns` | string |  | Inclusive UTC Unix nanoseconds; supply together with end_ns. |


### `carve_subpcap_for_connection`

Produce a bidirectional sub-PCAP for an explicit TCP/UDP tuple. format=evidence exports a ZIP containing PCAPNG and provenance manifest instead. Optional inclusive capture-time bounds narrow tuple reuse; omitting bounds selects all matching occurrences.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `dst_port` | string | yes | Destination port. |
| `end_ns` | string |  | Inclusive UTC Unix nanoseconds; supply together with start_ns. |
| `format` | string |  | pcap (default) or evidence ZIP with verifiable provenance. |
| `protocol` | string | yes | Observed transport protocol. |
| `run_id` | string |  | Expected capture generation; stale generations are rejected by the backend. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP. |
| `src_port` | string | yes | Source port. |
| `start_ns` | string |  | Inclusive UTC Unix nanoseconds; supply together with end_ns. |


### `carve_subpcap_for_host`

Produce a sub-PCAP filtered to all traffic involving one host IP. Returns the carved file's on-disk path, sha256, and an netcap://carve/{id} resource URI for direct byte access.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `host` | string | yes | Host IP (v4 or v6). |
| `run_id` | string |  | Expected capture generation; stale generations are rejected by the backend. |
| `session_id` | string | yes | Session identifier. |


### `carve_subpcap_for_http_pair`

Produce a bidirectional sub-PCAP for the observed HTTP TCP tuple, including nonstandard ports. Without time bounds, all matching tuple occurrences are included.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `dst_port` | string | yes | Observed destination port. |
| `end_ns` | string |  | Inclusive UTC Unix nanoseconds; supply together with start_ns. |
| `run_id` | string |  | Expected capture generation; stale generations are rejected by the backend. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP. |
| `src_port` | string | yes | Observed source port. |
| `start_ns` | string |  | Inclusive UTC Unix nanoseconds; supply together with end_ns. |


### `change_behavior`

Change behavioral baseline state or inventory using the exact version from get_behavior (optimistic concurrency). Actions are approve, pause, resume, relearn, reset, acknowledge, approve-changes, suppress, unsuppress, inventory. IDs select facts; inventory edits use inventory.id. Backend validates reasons, readiness and stale versions.

**Hints:** destructive

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "action": {
      "enum": [
        "approve",
        "pause",
        "resume",
        "relearn",
        "reset",
        "acknowledge",
        "approve-changes",
        "suppress",
        "unsuppress",
        "inventory"
      ],
      "type": "string"
    },
    "ids": {
      "items": {
        "type": "string"
      },
      "type": [
        "null",
        "array"
      ]
    },
    "inventory": {
      "additionalProperties": false,
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "notes": {
          "type": "string"
        },
        "prefix": {
          "type": "string"
        },
        "role": {
          "type": "string"
        }
      },
      "required": [
        "id"
      ],
      "type": [
        "null",
        "object"
      ]
    },
    "reason": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "version": {
      "maximum": 9007199254740991,
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "action",
    "version",
    "reason"
  ],
  "type": "object"
}
```

### `configure_protobuf`

Manage the complete custom Protobuf configuration lifecycle: add/remove path, map/unmap port, set showAlternatives, or recompile. Read get_protobuf_status afterward. Current configuration is forwarded to subsequent helper analyses and child reanalysis; no existing result is rewritten.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "messageType": {
      "type": "string"
    },
    "operation": {
      "enum": [
        "add-path",
        "remove-path",
        "map-port",
        "unmap-port",
        "preferences",
        "recompile"
      ],
      "type": "string"
    },
    "path": {
      "type": "string"
    },
    "port": {
      "type": "integer"
    },
    "showAlternatives": {
      "anyOf": [
        {
          "type": "boolean"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "operation"
  ],
  "type": "object"
}
```

### `delete_live_capture`

Delete one completed owned local live capture and its output, freeing the eight-capture capacity. Explicit session_id required; running captures must first be stopped and reach completion. Ordinary uploads and foreign directories are never removed.

**Hints:** destructive

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Owned live capture ID or input selector.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `delete_session`

Delete a terminal owned upload and its result artifacts in local or service mode. Queued/running analyses, preloaded captures and external original files are protected. Retained MCP artifacts for that session are also removed.

**Hints:** destructive, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Owned upload analysis ID returned by ingest_pcap. |


### `evaluate_firewall_policy`

Parse/compile an actual firewall policy bundle and optionally replay up to 1000 synthetic events with isolated state and suppressed effects. Returns revision, normalized policy and decisions. No live target, listener, deployment or response action is changed; use the firewall's native scoped MCP for CAS/idempotent deployment.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "bundle": {
      "type": "string"
    },
    "events": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "attributes": {
            "additionalProperties": {
              "type": "string"
            },
            "type": [
              "object",
              "null"
            ]
          },
          "body": {
            "type": "string"
          },
          "client_ip": {
            "type": "string"
          },
          "dns": {
            "additionalProperties": false,
            "properties": {
              "name": {
                "type": "string"
              },
              "type": {
                "type": "integer"
              }
            },
            "required": [],
            "type": "object"
          },
          "fields": {
            "additionalProperties": {
              "type": "string"
            },
            "type": [
              "object",
              "null"
            ]
          },
          "headers": {
            "additionalProperties": {
              "items": {
                "type": "string"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "type": [
              "object",
              "null"
            ]
          },
          "host": {
            "type": "string"
          },
          "method": {
            "type": "string"
          },
          "modbus": {
            "additionalProperties": false,
            "properties": {
              "address": {
                "type": "integer"
              },
              "end_address": {
                "type": "integer"
              },
              "function": {
                "type": "integer"
              },
              "is_write": {
                "type": "boolean"
              },
              "quantity": {
                "type": "integer"
              },
              "read_address": {
                "type": "integer"
              },
              "read_end_address": {
                "type": "integer"
              },
              "read_quantity": {
                "type": "integer"
              },
              "unit_id": {
                "type": "integer"
              }
            },
            "required": [],
            "type": "object"
          },
          "network": {
            "additionalProperties": false,
            "properties": {
              "direction": {
                "type": "string"
              },
              "dst_ip": {
                "type": "string"
              },
              "dst_port": {
                "type": "integer"
              },
              "ip_version": {
                "type": "integer"
              },
              "src_ip": {
                "type": "string"
              },
              "src_port": {
                "type": "integer"
              },
              "tcp_flags": {
                "type": "integer"
              },
              "transport": {
                "type": "string"
              }
            },
            "required": [],
            "type": "object"
          },
          "path": {
            "type": "string"
          },
          "phase": {
            "type": "string"
          },
          "protocol": {
            "type": "string"
          },
          "raw_query": {
            "type": "string"
          },
          "record_type": {
            "type": "string"
          },
          "status": {
            "type": "integer"
          },
          "tls": {
            "additionalProperties": false,
            "properties": {
              "alpn": {
                "type": "string"
              },
              "encrypted": {
                "type": "boolean"
              },
              "ja4": {
                "type": "string"
              },
              "server_name": {
                "type": "string"
              }
            },
            "required": [],
            "type": "object"
          }
        },
        "required": [
          "protocol"
        ],
        "type": "object"
      },
      "type": [
        "array",
        "null"
      ]
    }
  },
  "required": [
    "bundle"
  ],
  "type": "object"
}
```

### `execute_detection_rules`

Execute all enabled netcap detection rules against the session. SYNCHRONOUS: blocks until completion. The response includes per-rule execution results; new alerts also appear in list_alerts.

**Hints:** idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `execute_offline_rule_pack`

Execute a validated inline offline rule pack on one completed session with backend finite scan limits. Persists an evaluation and alerts; inspect list_offline_evaluations and list_alerts. Does not replace capture results.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "yaml": {
      "description": "Complete offline rule pack YAML.",
      "type": "string"
    }
  },
  "required": [
    "yaml",
    "session_id"
  ],
  "type": "object"
}
```

### `execute_yara_scan`

Run all loaded YARA rules against the session's extracted files. SYNCHRONOUS: this call blocks until the scan completes (typically seconds to a few minutes; HTTP client timeout is 5 min). The response contains the full set of matches.

**Hints:** idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `export_packet_evidence`

Export a bounded BPF/time selection from the bound original PCAP or one explicitly retained live segment as a provenance ZIP. Requires runId and sourceSHA256 from get_capture_evidence; for live traffic select a retained segment name and its SHA256. Active/expired/changed segments fail. Source cap 256 MiB, ZIP cap 16 MiB; narrow BPF/time/maxPackets rather than accepting silent truncation. Read returned artifact with read_mcp_artifact.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "bpf": {
      "description": "BPF selection, default all packets.",
      "type": "string"
    },
    "endNs": {
      "description": "Inclusive exact capture-time nanoseconds; paired with startNs.",
      "type": "string"
    },
    "maxPackets": {
      "description": "Selected packet limit, default 1000000; overflow is an error.",
      "maximum": 1000000,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "runId": {
      "description": "Expected capture run id.",
      "type": "string"
    },
    "segment": {
      "description": "Optional exact retained segment name from capture manifest.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "sourceSHA256": {
      "description": "Original input hash, or selected retained segment hash.",
      "type": "string"
    },
    "startNs": {
      "description": "Inclusive exact capture-time nanoseconds; paired with endNs.",
      "type": "string"
    }
  },
  "required": [
    "runId",
    "sourceSHA256",
    "session_id"
  ],
  "type": "object"
}
```

### `extract_iocs_from_file`

Scan one carved file for indicators of compromise: URLs, hostnames, domains, IPv4/IPv6 addresses, and email addresses. By default all kinds are returned; restrict via `kinds` (CSV of url,domain,ip,email). File is fetched via the same path semantics as get_extracted_file_content.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `file_path` | string | yes | Relative path inside files/, as returned by list_extracted_files. |
| `kinds` | string |  | CSV of IOC kinds to extract. Allowed: url,domain,ip,email. Default: all. |
| `max_per_kind` | number |  | Cap distinct matches returned per kind (default 200, max 5000). |
| `session_id` | string | yes | Session identifier. |


### `flow_receiver`

Owned UDP NetFlow/IPFIX/sFlow receiver lifecycle using the native decoder/recorder. start requires literal loopback listen (port 0 supported), duration_seconds 1..300 and max_output_mb 1..8. Returns receiver_id/address; status reports health, stop finalizes, query uses an explicit exporter/format/domain/time scope after completion, delete removes owned records. Shares the eight-job bound; byte budget is checked after each bounded datagram. Raw UDP exporter addresses are not authenticated identities.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "duration_seconds": {
      "type": "integer"
    },
    "listen": {
      "type": "string"
    },
    "max_output_mb": {
      "type": "integer"
    },
    "operation": {
      "enum": [
        "start",
        "status",
        "stop",
        "query",
        "delete"
      ],
      "type": "string"
    },
    "query": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "domain": {
              "anyOf": [
                {
                  "minimum": 0,
                  "type": "integer"
                },
                {
                  "type": "null"
                }
              ]
            },
            "egress": {
              "type": "string"
            },
            "endNs": {
              "type": "string"
            },
            "exporter": {
              "type": "string"
            },
            "format": {
              "type": "string"
            },
            "groupBy": {
              "type": "string"
            },
            "host": {
              "type": "string"
            },
            "ingress": {
              "type": "string"
            },
            "limit": {
              "type": "integer"
            },
            "nextHop": {
              "type": "string"
            },
            "startNs": {
              "type": "string"
            },
            "timeBasis": {
              "type": "string"
            }
          },
          "required": [
            "startNs",
            "endNs",
            "timeBasis",
            "exporter",
            "format",
            "groupBy",
            "limit"
          ],
          "type": "object"
        },
        {
          "type": "null"
        }
      ]
    },
    "receiver_id": {
      "type": "string"
    }
  },
  "required": [
    "operation"
  ],
  "type": "object"
}
```

### `generate_protocol_cases`

Generate deterministic grammar/field/setup-step campaign cases offline, preserving control, configuration hashes and target/reset declarations. No packets are sent.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "control": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "type": "string"
        },
        "clientCertificateFile": {
          "type": "string"
        },
        "clientKeyFile": {
          "type": "string"
        },
        "framing": {
          "additionalProperties": false,
          "properties": {
            "byteOrder": {
              "type": "string"
            },
            "delimiter": {
              "contentEncoding": "base64",
              "type": [
                "string",
                "null"
              ]
            },
            "fixedSize": {
              "type": "integer"
            },
            "kind": {
              "type": "string"
            },
            "lengthBytes": {
              "type": "integer"
            },
            "lengthIncludesHeader": {
              "type": "boolean"
            },
            "maxBytes": {
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "maxBytes"
          ],
          "type": "object"
        },
        "maxTotalBytes": {
          "type": "integer"
        },
        "network": {
          "type": "string"
        },
        "peerCertificateSHA256": {
          "type": "string"
        },
        "rootCAFile": {
          "type": "string"
        },
        "serverName": {
          "type": "string"
        },
        "serverTLS": {
          "anyOf": [
            {
              "additionalProperties": false,
              "properties": {
                "certificateFile": {
                  "type": "string"
                },
                "clientCAFile": {
                  "type": "string"
                },
                "keyFile": {
                  "type": "string"
                },
                "peerCertificateSHA256": {
                  "type": "string"
                }
              },
              "required": [
                "certificateFile",
                "keyFile"
              ],
              "type": "object"
            },
            {
              "type": "null"
            }
          ]
        },
        "steps": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "captureLength": {
                "type": "integer"
              },
              "captureOffset": {
                "type": "integer"
              },
              "captureVariable": {
                "type": "string"
              },
              "contains": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expect": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expectPresent": {
                "type": "boolean"
              },
              "name": {
                "type": "string"
              },
              "receive": {
                "type": "boolean"
              },
              "send": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "sendPresent": {
                "type": "boolean"
              },
              "sendVariable": {
                "type": "string"
              }
            },
            "required": [
              "name",
              "receive"
            ],
            "type": "object"
          },
          "type": [
            "array",
            "null"
          ]
        },
        "timeoutMilliseconds": {
          "type": "integer"
        },
        "tls": {
          "type": "boolean"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "network",
        "address",
        "tls",
        "framing",
        "timeoutMilliseconds",
        "maxTotalBytes",
        "steps"
      ],
      "type": "object"
    },
    "failureMarker": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "generation": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "buildSeed": {
              "type": "boolean"
            },
            "bytes": {
              "type": "boolean"
            },
            "fields": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "name": {
                    "type": "string"
                  },
                  "values": {
                    "items": {
                      "contentEncoding": "base64",
                      "type": [
                        "string",
                        "null"
                      ]
                    },
                    "type": [
                      "array",
                      "null"
                    ]
                  }
                },
                "required": [
                  "name"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "grammar": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "fields": {
                      "items": {
                        "additionalProperties": false,
                        "properties": {
                          "byteOrder": {
                            "type": "string"
                          },
                          "expected": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "hypothesis": {
                            "type": "string"
                          },
                          "kind": {
                            "type": "string"
                          },
                          "length": {
                            "type": "integer"
                          },
                          "lengthFrom": {
                            "anyOf": [
                              {
                                "additionalProperties": false,
                                "properties": {
                                  "adjustment": {
                                    "type": "integer"
                                  },
                                  "byteOrder": {
                                    "type": "string"
                                  },
                                  "offset": {
                                    "type": "integer"
                                  },
                                  "width": {
                                    "type": "integer"
                                  }
                                },
                                "required": [
                                  "offset",
                                  "width",
                                  "byteOrder",
                                  "adjustment"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "name": {
                            "type": "string"
                          },
                          "offset": {
                            "type": "integer"
                          },
                          "tlv": {
                            "anyOf": [
                              {
                                "additionalProperties": false,
                                "properties": {
                                  "byteOrder": {
                                    "type": "string"
                                  },
                                  "leafKind": {
                                    "type": "string"
                                  },
                                  "lengthBytes": {
                                    "type": "integer"
                                  },
                                  "lengthIncludesHeader": {
                                    "type": "boolean"
                                  },
                                  "maxDepth": {
                                    "type": "integer"
                                  },
                                  "maxEntries": {
                                    "type": "integer"
                                  },
                                  "maxValueBytes": {
                                    "type": "integer"
                                  },
                                  "nestedTypes": {
                                    "items": {
                                      "minimum": 0,
                                      "type": "integer"
                                    },
                                    "type": [
                                      "array",
                                      "null"
                                    ]
                                  },
                                  "typeBytes": {
                                    "type": "integer"
                                  }
                                },
                                "required": [
                                  "typeBytes",
                                  "lengthBytes",
                                  "byteOrder",
                                  "lengthIncludesHeader",
                                  "leafKind",
                                  "maxDepth",
                                  "maxEntries",
                                  "maxValueBytes"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          }
                        },
                        "required": [
                          "name",
                          "offset",
                          "length",
                          "kind",
                          "hypothesis"
                        ],
                        "type": "object"
                      },
                      "type": [
                        "array",
                        "null"
                      ]
                    },
                    "framing": {
                      "additionalProperties": false,
                      "properties": {
                        "byteOrder": {
                          "type": "string"
                        },
                        "delimiter": {
                          "contentEncoding": "base64",
                          "type": [
                            "string",
                            "null"
                          ]
                        },
                        "fixedSize": {
                          "type": "integer"
                        },
                        "kind": {
                          "type": "string"
                        },
                        "lengthBytes": {
                          "type": "integer"
                        },
                        "lengthIncludesHeader": {
                          "type": "boolean"
                        },
                        "maxBytes": {
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "maxBytes"
                      ],
                      "type": "object"
                    },
                    "maxFrames": {
                      "type": "integer"
                    },
                    "version": {
                      "type": "integer"
                    }
                  },
                  "required": [
                    "version",
                    "framing",
                    "fields",
                    "maxFrames"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "states": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "action": {
                    "type": "string"
                  },
                  "step": {
                    "type": "integer"
                  }
                },
                "required": [
                  "action",
                  "step"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "version": {
              "type": "integer"
            }
          },
          "required": [
            "version",
            "bytes",
            "buildSeed"
          ],
          "type": "object"
        },
        {
          "type": "null"
        }
      ]
    },
    "maxAttempts": {
      "type": "integer"
    },
    "maxCases": {
      "type": "integer"
    },
    "metadata": {
      "additionalProperties": false,
      "properties": {
        "reset": {
          "additionalProperties": false,
          "properties": {
            "description": {
              "type": "string"
            },
            "exchange": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "address": {
                      "type": "string"
                    },
                    "clientCertificateFile": {
                      "type": "string"
                    },
                    "clientKeyFile": {
                      "type": "string"
                    },
                    "framing": {
                      "additionalProperties": false,
                      "properties": {
                        "byteOrder": {
                          "type": "string"
                        },
                        "delimiter": {
                          "contentEncoding": "base64",
                          "type": [
                            "string",
                            "null"
                          ]
                        },
                        "fixedSize": {
                          "type": "integer"
                        },
                        "kind": {
                          "type": "string"
                        },
                        "lengthBytes": {
                          "type": "integer"
                        },
                        "lengthIncludesHeader": {
                          "type": "boolean"
                        },
                        "maxBytes": {
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "maxBytes"
                      ],
                      "type": "object"
                    },
                    "maxTotalBytes": {
                      "type": "integer"
                    },
                    "network": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    },
                    "rootCAFile": {
                      "type": "string"
                    },
                    "serverName": {
                      "type": "string"
                    },
                    "serverTLS": {
                      "anyOf": [
                        {
                          "additionalProperties": false,
                          "properties": {
                            "certificateFile": {
                              "type": "string"
                            },
                            "clientCAFile": {
                              "type": "string"
                            },
                            "keyFile": {
                              "type": "string"
                            },
                            "peerCertificateSHA256": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "certificateFile",
                            "keyFile"
                          ],
                          "type": "object"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    },
                    "steps": {
                      "items": {
                        "additionalProperties": false,
                        "properties": {
                          "captureLength": {
                            "type": "integer"
                          },
                          "captureOffset": {
                            "type": "integer"
                          },
                          "captureVariable": {
                            "type": "string"
                          },
                          "contains": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expect": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expectPresent": {
                            "type": "boolean"
                          },
                          "name": {
                            "type": "string"
                          },
                          "receive": {
                            "type": "boolean"
                          },
                          "send": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "sendPresent": {
                            "type": "boolean"
                          },
                          "sendVariable": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "name",
                          "receive"
                        ],
                        "type": "object"
                      },
                      "type": [
                        "array",
                        "null"
                      ]
                    },
                    "timeoutMilliseconds": {
                      "type": "integer"
                    },
                    "tls": {
                      "type": "boolean"
                    },
                    "version": {
                      "type": "integer"
                    }
                  },
                  "required": [
                    "version",
                    "network",
                    "address",
                    "tls",
                    "framing",
                    "timeoutMilliseconds",
                    "maxTotalBytes",
                    "steps"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "mode": {
              "type": "string"
            }
          },
          "required": [
            "mode",
            "description"
          ],
          "type": "object"
        },
        "targetVersion": {
          "type": "string"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "targetVersion",
        "reset"
      ],
      "type": "object"
    },
    "responseStep": {
      "type": "integer"
    },
    "sendStep": {
      "type": "integer"
    }
  },
  "required": [
    "metadata",
    "control",
    "sendStep",
    "responseStep",
    "failureMarker",
    "maxCases",
    "maxAttempts"
  ],
  "type": "object"
}
```

### `generate_protocol_corpus`

Generate versioned control/truncation/XOR byte cases offline. data is base64; explicit maxCases/maxBytes bound output.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "data": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "maxBytes": {
      "type": "integer"
    },
    "maxCases": {
      "type": "integer"
    },
    "targetVersion": {
      "type": "string"
    }
  },
  "required": [
    "data",
    "maxCases",
    "maxBytes",
    "targetVersion"
  ],
  "type": "object"
}
```

### `get_alert_stats`

Summary statistics for alerts in this session.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `get_analysis_config`

Read configuration for an explicitly selected capture without changing global selection. get_capture_evidence supplies the retained producer's effective settings and provenance.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_analysis_settings`

Discover actual future-analysis DPI support/module selection, payload capture, bounded retention/state budgets, incremental HTTP, capture-time expiry and flow-export configuration. Scope is process-wide; existing results are unchanged.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `get_analyst_binding`

Get explicit registered capture binding for analyst version 1 workflows; diagnostic=true permits failed captures for log review.

**Hints:** read-only

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `diagnostic` | boolean |  |  |
| `inputFile` | string |  |  |
| `sessionId` | string |  |  |


### `get_analyst_capabilities`

Read analyst contract versions, finite limits, explicit-source policy and supported catalogue field paths. No capture is selected or scanned.

**Hints:** read-only

**Arguments:** none


### `get_artifact_analysis`

Read artifact analysis and extraction qualification report. Unavailable/legacy evidence is an explicit error.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_asset_context`

Read qualified asset context, learned facts and inventory for one observed asset.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "asset": {
      "description": "Asset identifier from get_behavior.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "asset",
    "session_id"
  ],
  "type": "object"
}
```

### `get_audit_record_fields`

Return the field schema for one audit record type: name, Go-style type (string/int/bool/repeated/struct), and whether it's nested. Use the returned field names in query_audit_records' filter expressions.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `type` | string | yes | Audit record type name without the NC_ prefix, e.g. "DNS". |


### `get_audit_record_values`

For one audit record type in a session, return the distinct observed values per field (a fast cardinality snapshot — useful before crafting a filter).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |
| `type` | string | yes | Audit record type name without the NC_ prefix. |


### `get_behavior`

Read behavioral baseline version, mode, learning/coverage counters and collection counts with one bounded fact/inventory page. Default section=observed, limit=25. Entries retain original keyed values; pass section=summary for metadata only. Version is required for change_behavior.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "description": "Entries per page (default 25).",
      "maximum": 100,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "offset": {
      "description": "Entry offset in sorted-key order (decision history keeps its stored order).",
      "maximum": 100000,
      "minimum": 0,
      "multipleOf": 1,
      "type": "number"
    },
    "section": {
      "description": "Collection to page, or summary for metadata only.",
      "enum": [
        "summary",
        "observed",
        "approved",
        "labels",
        "corrections",
        "leases",
        "rates",
        "approvedRates",
        "activity",
        "suppressed",
        "decisions"
      ],
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_behavior_health`

Read behavioral detection coverage and health qualifications.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_behavior_records`

Read bounded Connection/SMB candidates for one behavioral alert. Preserve tuple/time-only qualification and truncation; these are not exact occurrence bindings.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "alertId": {
      "description": "Alert identifier from list_alerts.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "alertId",
    "session_id"
  ],
  "type": "object"
}
```

### `get_behavior_topology`

Read bounded behavioral topology as JSON.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "maxNodes": {
      "description": "Maximum nodes.",
      "maximum": 500,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "scope": {
      "description": "Optional topology scope.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_bpf_config`

Read the persisted BPF filter and syntax examples used for future analyses.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `get_capability_inventory`

Discover every capture MCP workflow, exact tool coverage, native scoped firewall MCP entrypoints and explicit configuration-only boundaries. Does not contact other servers or share credentials.

**Hints:** read-only

**Arguments:** none


### `get_capture_evidence`

Read capture run/source identity, effective configuration, packet-retention coverage and producer health. Missing evidence is an error. Oversized manifests return a complete JSON artifact; select fields for bounded structured inspection.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "fields": {
      "description": "Comma-separated top-level fields or JSON Pointer paths, e.g. runId,inputSHA256 or /interfaces/0.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_chart_data`

Aggregate one audit-record field as a time series. Useful for beacon detection (regular interval connections), DGA hunts, or any per-field-over-time analytics. Returns JSON: {type, field, interval, data: [{timestamp, value}], count, min_value, max_value, avg_value}.

Use get_audit_record_fields to discover available fields.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `field` | string | yes | Field to aggregate (numeric or boolean). Use dot notation for nested fields, e.g. "Questions[0].Name". |
| `interval` | string |  | Bucket size as a Go duration string (1s, 100ms, 1m, 1h). Default 1s. |
| `max_data_points` | number |  | Down-sample to this many points. Default 1000, max 10000. |
| `session_id` | string | yes | Session identifier. |
| `type` | string | yes | Audit record type name (no NC_ prefix), e.g. "Connection". |


### `get_conversation`

Return a bounded presentation-conversation page for an explicit TCP/UDP tuple. Use get_stream_content for verified directional bytes and loss metadata.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `dst_ip` | string | yes | Destination IP. |
| `dst_port` | string | yes | Destination port. |
| `limit` | number |  | Conversation byte count, default 1024. |
| `offset` | number |  | Conversation byte offset. |
| `protocol` | string |  | Transport, default TCP. |
| `session_id` | string | yes | Session identifier. |
| `src_ip` | string | yes | Source IP. |
| `src_port` | string | yes | Source port. |


### `get_decoder_config`

Read the persisted decoder selection for future analyses.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `get_extracted_file_content`

Return a chunk of one extracted file's bytes, hex-encoded. The backing endpoint paginates: offset/limit slice into the file (limit is capped at 64 KiB per call). Use this to inspect a suspicious carved payload before running YARA or a disassembler.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `file_path` | string | yes | Relative path of the file inside the session's files/ directory, as returned by list_extracted_files. |
| `limit` | number |  | Number of bytes to read (default 16384, max 65536). |
| `offset` | number |  | Byte offset to start reading from (default 0). |
| `session_id` | string | yes | Session identifier. |


### `get_features`

Discover optional features, enabled state, startup flags and whether changes affect queries or future captures.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `get_image_exif`

Parse EXIF metadata from a carved image file. Returns a flat list of {ifd_path, tag_id, tag_name, type_name, value} entries. Returns an empty list (not an error) when the file carries no EXIF segment.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `file_path` | string | yes | Relative path inside files/, as returned by list_extracted_files. |
| `session_id` | string | yes | Session identifier. |


### `get_investigation_health`

Read FTP data-channel or TCP reassembly health, including partial/lost evidence qualifications.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "kind": {
      "description": "Health report.",
      "enum": [
        "ftp",
        "reassembly"
      ],
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "kind",
    "session_id"
  ],
  "type": "object"
}
```

### `get_live_capture_status`

Read owned live-capture completion/error/deadline and backend live state. Optional session_id pins the owned capture. Legacy backend status remains available without a selector.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string |  | Optional owned capture ID from start_live_capture. |


### `get_network_detection`

Read capture-time network detector statistics, limits and dropped/unsupported evidence; inspect emitted detections with list_alerts.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_operator_bindings`

Discover optional startup-enrolled sensor/webhook binding names, limits and configured/network state. No keys, credential references, namespace paths or webhook URLs are returned. Empty enrollment is explicitly unconfigured.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `get_protobuf_status`

Read loaded custom Protobuf schemas, compile errors and port mappings.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `get_protocol_hierarchy`

Wireshark-style nested protocol hierarchy as JSON: layer counts and bytes.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `get_protocol_job`

Poll one owned protocol job; running returns actual address/deadline, completion returns the full report or bounded artifact reference and errors. consume=true removes a completed job after returning its immutable result.

**Hints:** destructive, open-world

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `consume` | boolean |  |  |
| `job_id` | string | yes |  |


### `get_related_evidence`

Find qualified related records through an evidence id, type+ordinal, or observation identity. Links retain certainty, missing coverage and limitations; use resolve_audit_occurrence for content-bound exact resolution.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "communityId": {
      "description": "Community ID.",
      "type": "string"
    },
    "id": {
      "description": "Evidence id.",
      "type": "string"
    },
    "observationId": {
      "description": "Connection observation id.",
      "type": "string"
    },
    "ordinal": {
      "description": "Zero-based audit ordinal.",
      "maximum": 1000000000,
      "minimum": 0,
      "multipleOf": 1,
      "type": "number"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "time": {
      "description": "Exact decimal timestamp nanoseconds.",
      "type": "string"
    },
    "type": {
      "description": "Audit type.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_reproduction_metadata`

Export metadata-only reproduction evidence, including failed captures. No source paths, raw logs or packet bodies. Optional runId binds generation.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "runId": {
      "description": "Expected capture run id.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_session_info`

Return metadata for one analysis session: completion status, error message if any, input filename and size, per-record-type audit counts and capture_provenance (runId/inputSHA256) when available. Missing provenance has an explicit error field. Use this to poll ingest or child analysis.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier returned by ingest_pcap or list_sessions. |


### `get_stream_content`

Read a verified directional stream page as base64, retaining manifest hash, status, loss limitations and a bounded span page (timestamps, gaps, datagram boundaries). Subsequent byte offsets require manifestSHA256 from the first response. No execution or complete-coverage claim is inferred.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "direction": {
      "description": "Direction.",
      "enum": [
        "client",
        "server"
      ],
      "type": "string"
    },
    "id": {
      "description": "stream-* id from get_stream_evidence.",
      "type": "string"
    },
    "limit": {
      "description": "Bytes per page, default 65536.",
      "maximum": 65536,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "manifestSHA256": {
      "description": "Required on subsequent pages.",
      "type": "string"
    },
    "offset": {
      "description": "Byte offset.",
      "maximum": 268435456,
      "minimum": 0,
      "multipleOf": 1,
      "type": "number"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "spanLimit": {
      "description": "Manifest spans per page, default 64.",
      "maximum": 128,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "spanOffset": {
      "description": "Manifest span offset.",
      "maximum": 1000000,
      "minimum": 0,
      "multipleOf": 1,
      "type": "number"
    }
  },
  "required": [
    "id",
    "direction",
    "session_id"
  ],
  "type": "object"
}
```

### `get_stream_evidence`

List retained stream manifests (up to 1000 streams, span bodies omitted), or get one exact manifest by id and direction=manifest. Binary stream bodies are not returned by this tool.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "direction": {
      "description": "Set manifest when supplying id.",
      "enum": [
        "manifest"
      ],
      "type": "string"
    },
    "id": {
      "description": "Optional stream-* id from this session.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_timeline_buckets`

Read bounded per-track timeline density buckets with generation and coverage qualifications.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "buckets": {
      "description": "Number of density buckets.",
      "maximum": 500,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "communityId": {
      "description": "Community ID filter.",
      "type": "string"
    },
    "end": {
      "description": "Exact decimal end nanoseconds.",
      "type": "string"
    },
    "generation": {
      "description": "Generation returned by get_timeline_meta; required with cursors.",
      "type": "string"
    },
    "host": {
      "description": "Host filter.",
      "type": "string"
    },
    "q": {
      "description": "Search text.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "start": {
      "description": "Exact decimal start nanoseconds.",
      "type": "string"
    },
    "types": {
      "description": "CSV of timeline tracks from get_timeline_meta.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_timeline_meta`

Discover timeline tracks, capture time bounds and generation for stable event pagination.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `get_yara_status`

Return YARA engine status (enabled, rule count, last reload).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `import_protocol_triage`

Import explicitly labeled external crash/sanitizer evidence verbatim with generation, target and reset declarations. No execution or inferred RCE.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "artifact": {
      "type": "string"
    },
    "data": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "generation": {
      "type": "string"
    },
    "kind": {
      "type": "string"
    },
    "reset": {
      "type": "string"
    },
    "targetVersion": {
      "type": "string"
    }
  },
  "required": [
    "kind",
    "targetVersion",
    "reset",
    "generation",
    "data",
    "artifact"
  ],
  "type": "object"
}
```

### `ingest_pcap`

Ingest a local PCAP/PCAPNG file into a new netcap analysis session. Returns immediately with a session_id; ingest runs asynchronously. Poll get_session_info until the session reports completed=true before running analytical tools. Configure future analyses with set_bpf_config, set_decoder_config and set_feature first. Legacy per-ingest options are rejected because the upload API cannot honor them.

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `path` | string | yes | Absolute filesystem path of the .pcap or .pcapng file to ingest. |


### `inspect_bound_capture`

Bounded original capture metadata, interfaces, exact time bounds, wire/captured bytes, truncation and ordering. Verify the stored source hash against the included run.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "type": "object",
  "properties": {
    "source": {
      "type": "object",
      "properties": {
        "sessionId": {
          "type": "string"
        },
        "inputFile": {
          "type": "string"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        }
      },
      "required": [
        "binding"
      ],
      "additionalProperties": false
    }
  },
  "required": [
    "source"
  ],
  "additionalProperties": false
}
```

### `interpret_protocol_grammar`

Interpret a bounded directional byte sequence using explicit framing/field/TLV hypotheses; optional compare returns differences. data/compare are base64. Parsing is not proof of protocol semantics; retain stream loss qualifications.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "compare": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "data": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "grammar": {
      "additionalProperties": false,
      "properties": {
        "fields": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "byteOrder": {
                "type": "string"
              },
              "expected": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "hypothesis": {
                "type": "string"
              },
              "kind": {
                "type": "string"
              },
              "length": {
                "type": "integer"
              },
              "lengthFrom": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "adjustment": {
                        "type": "integer"
                      },
                      "byteOrder": {
                        "type": "string"
                      },
                      "offset": {
                        "type": "integer"
                      },
                      "width": {
                        "type": "integer"
                      }
                    },
                    "required": [
                      "offset",
                      "width",
                      "byteOrder",
                      "adjustment"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "name": {
                "type": "string"
              },
              "offset": {
                "type": "integer"
              },
              "tlv": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "byteOrder": {
                        "type": "string"
                      },
                      "leafKind": {
                        "type": "string"
                      },
                      "lengthBytes": {
                        "type": "integer"
                      },
                      "lengthIncludesHeader": {
                        "type": "boolean"
                      },
                      "maxDepth": {
                        "type": "integer"
                      },
                      "maxEntries": {
                        "type": "integer"
                      },
                      "maxValueBytes": {
                        "type": "integer"
                      },
                      "nestedTypes": {
                        "items": {
                          "minimum": 0,
                          "type": "integer"
                        },
                        "type": [
                          "array",
                          "null"
                        ]
                      },
                      "typeBytes": {
                        "type": "integer"
                      }
                    },
                    "required": [
                      "typeBytes",
                      "lengthBytes",
                      "byteOrder",
                      "lengthIncludesHeader",
                      "leafKind",
                      "maxDepth",
                      "maxEntries",
                      "maxValueBytes"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              }
            },
            "required": [
              "name",
              "offset",
              "length",
              "kind",
              "hypothesis"
            ],
            "type": "object"
          },
          "type": [
            "array",
            "null"
          ]
        },
        "framing": {
          "additionalProperties": false,
          "properties": {
            "byteOrder": {
              "type": "string"
            },
            "delimiter": {
              "contentEncoding": "base64",
              "type": [
                "string",
                "null"
              ]
            },
            "fixedSize": {
              "type": "integer"
            },
            "kind": {
              "type": "string"
            },
            "lengthBytes": {
              "type": "integer"
            },
            "lengthIncludesHeader": {
              "type": "boolean"
            },
            "maxBytes": {
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "maxBytes"
          ],
          "type": "object"
        },
        "maxFrames": {
          "type": "integer"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "framing",
        "fields",
        "maxFrames"
      ],
      "type": "object"
    }
  },
  "required": [
    "grammar",
    "data"
  ],
  "type": "object"
}
```

### `interpret_stream_grammar`

Interpret or compare retained directional TCP bytes (at most 16 MiB each) under an explicit grammar. Requires the manifest SHA256 from get_stream_content; refuses gaps, discarded bytes and datagrams. Sources remain session-confined; large reports become bounded readable MCP artifacts.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "compareDirection": {
      "type": "string"
    },
    "compareId": {
      "type": "string"
    },
    "compareManifestSHA256": {
      "type": "string"
    },
    "direction": {
      "enum": [
        "client",
        "server"
      ],
      "type": "string"
    },
    "grammar": {
      "additionalProperties": false,
      "properties": {
        "fields": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "byteOrder": {
                "type": "string"
              },
              "expected": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "hypothesis": {
                "type": "string"
              },
              "kind": {
                "type": "string"
              },
              "length": {
                "type": "integer"
              },
              "lengthFrom": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "adjustment": {
                        "type": "integer"
                      },
                      "byteOrder": {
                        "type": "string"
                      },
                      "offset": {
                        "type": "integer"
                      },
                      "width": {
                        "type": "integer"
                      }
                    },
                    "required": [
                      "offset",
                      "width",
                      "byteOrder",
                      "adjustment"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "name": {
                "type": "string"
              },
              "offset": {
                "type": "integer"
              },
              "tlv": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "byteOrder": {
                        "type": "string"
                      },
                      "leafKind": {
                        "type": "string"
                      },
                      "lengthBytes": {
                        "type": "integer"
                      },
                      "lengthIncludesHeader": {
                        "type": "boolean"
                      },
                      "maxDepth": {
                        "type": "integer"
                      },
                      "maxEntries": {
                        "type": "integer"
                      },
                      "maxValueBytes": {
                        "type": "integer"
                      },
                      "nestedTypes": {
                        "items": {
                          "minimum": 0,
                          "type": "integer"
                        },
                        "type": [
                          "array",
                          "null"
                        ]
                      },
                      "typeBytes": {
                        "type": "integer"
                      }
                    },
                    "required": [
                      "typeBytes",
                      "lengthBytes",
                      "byteOrder",
                      "lengthIncludesHeader",
                      "leafKind",
                      "maxDepth",
                      "maxEntries",
                      "maxValueBytes"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              }
            },
            "required": [
              "name",
              "offset",
              "length",
              "kind",
              "hypothesis"
            ],
            "type": "object"
          },
          "type": [
            "array",
            "null"
          ]
        },
        "framing": {
          "additionalProperties": false,
          "properties": {
            "byteOrder": {
              "type": "string"
            },
            "delimiter": {
              "contentEncoding": "base64",
              "type": [
                "string",
                "null"
              ]
            },
            "fixedSize": {
              "type": "integer"
            },
            "kind": {
              "type": "string"
            },
            "lengthBytes": {
              "type": "integer"
            },
            "lengthIncludesHeader": {
              "type": "boolean"
            },
            "maxBytes": {
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "maxBytes"
          ],
          "type": "object"
        },
        "maxFrames": {
          "type": "integer"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "framing",
        "fields",
        "maxFrames"
      ],
      "type": "object"
    },
    "id": {
      "type": "string"
    },
    "manifestSHA256": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "id",
    "direction",
    "manifestSHA256",
    "grammar"
  ],
  "type": "object"
}
```

### `list_alerts`

Alerts raised in this session. Use group_id from a grouped result to page every member, with an independent alert-page generation.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `group_id` | string |  | Exact group identifier from list_alerts_grouped. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_alerts_grouped`

Bounded alert-group summaries with unique-value previews and exact totals. Retrieve full members with list_alerts(group_id). Pagination counts groups; groupCount is the number of groups and totalCount counts underlying alerts.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_audit_records`

List the audit-record files produced for one session (DNS.ncap.gz, HTTP.ncap.gz, Connection.ncap.gz, ...) with their record counts and on-disk sizes.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `list_auth_activity`

Read authentication observations from the explicitly selected capture, including TACACS+, Kerberos and credential-capture evidence.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "limit": {
      "description": "Events per page.",
      "maximum": 500,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "offset": {
      "description": "Event offset.",
      "maximum": 100000,
      "minimum": 0,
      "multipleOf": 1,
      "type": "number"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `list_bound_occurrences`

List at most 4096 exact occurrence references for one explicitly bound audit type; larger scopes must use catalogue search.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "type": "object",
  "properties": {
    "source": {
      "type": "object",
      "properties": {
        "sessionId": {
          "type": "string"
        },
        "inputFile": {
          "type": "string"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        }
      },
      "required": [
        "binding"
      ],
      "additionalProperties": false
    },
    "type": {
      "type": "string"
    }
  },
  "required": [
    "source",
    "type"
  ],
  "additionalProperties": false
}
```

### `list_certificates`

All TLS certificates observed in the session (issuer, subject, sans, validity).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_connections`

List all reconstructed connections in the session, with bytes/packets and timing. Use search/limit/offset to scope. The LLM can sort by total_size for top talkers.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_decoders`

List all available packet and stream decoders, with descriptions. Use the names returned here as includeDecoders / excludeDecoders on set_decoder_config before ingest_pcap or reanalyze_session.

**Hints:** read-only, idempotent

**Arguments:** none


### `list_devices`

List all devices (MAC addresses) seen in the session, with vendor lookups.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_domains`

Domains queried in the session, with counts. Sort by count client-side for a top-N view.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_extracted_files`

All files carved out of the session's traffic by netcap's file decoder. Each entry includes MIME type, size, source/destination IPs, and a relative path usable as `file_path` for get_extracted_file_content.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_fingerprints`

Cryptographic fingerprints (JA4/JA4S/JA4SSH) observed in the session.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_hosts`

List all hosts (IP profiles) seen in the session, with packet and byte counts. Use view=identity for scoped names, accounts and evidence, or view=directory for unattached directory observations. Identity availability and generation accompany every page.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |
| `view` | string |  | traffic (default), identity or directory; each view has independent pagination. |


### `list_http_records`

All HTTP records in the session (request + response details).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_network_interfaces`

Discover host interfaces before start_live_capture. No session is required; NC_LIVE_INTERFACES constrains capture admission when configured.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `list_offline_evaluations`

Read persisted offline rule evaluations, including errors and coverage limits for one completed session.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `list_offline_rule_packs`

Discover netcap-offline-rules/v1 YAML example and finite execution limits. Validate then execute a pack on a completed session.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `list_protobuf_messages`

Discover message types in the loaded custom Protobuf schema registry.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `list_rules`

List netcap detection rules available for execution.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_secrets`

Credentials / secrets recovered from cleartext protocols.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_services`

List all detected services (host+port+banner+product) in the session.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_sessions`

List analysis sessions visible to this server. In service mode this returns the operator's session inventory; in CLI mode it returns the pre-loaded session (if any) plus everything uploaded via ingest_pcap in this process. Response shape is identical across modes: every entry has session_id, mode, input_file, input_name, size_bytes, completed, status, plus mode-specific fields. Use limit/offset to paginate; completed_only filters to ready sessions.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `completed_only` | boolean |  | If true, return only sessions whose analysis has completed. |
| `failed_only` | boolean |  | If true, return only sessions in a failed state. |
| `limit` | number |  | Max sessions to return (default 100, max 500). |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Case-insensitive substring match against input_name and input_file. |


### `list_software`

Software products detected in the session (vendor/product/version, sourced from banners, JA4, user-agents, etc.).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fields` | string |  | Optional comma-separated fields or JSON Pointer paths. |
| `generation` | string |  | Generation from the previous page; changed collections reject continuation. |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_vulnerabilities`

Vulnerabilities flagged against detected software (CVE matches).

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `limit` | number |  | Maximum number of results to return. |
| `offset` | number |  | Pagination offset. |
| `search` | string |  | Substring filter applied server-side. |
| `session_id` | string | yes | Session identifier. |


### `list_yara_rules`

List YARA rules currently loaded for scanning extracted files.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string | yes | Session identifier. |


### `lookup_cve`

Fetch the NVD record for a CVE id: description, CVSS v3 score and vector, CWE classifications, references. Disabled (returns an error) when the server was constructed without AllowNetwork, or when NETCAP_MCP_DISABLE_NETWORK=1 in the environment. Results are cached in-process for 6h (positive) or 5min (negative).

**Hints:** read-only, idempotent, open-world

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `cve_id` | string | yes | CVE identifier, e.g. "CVE-2021-44228". |


### `lookup_dhcp_fingerprint`

Reports DHCP fingerprint enrichment as disabled pending an independently sourced catalogue. Packet decoding remains available; no network or legacy dataset access.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `fingerprint` | string | yes | DHCP option list, comma-separated (e.g. "1,3,6,15,33,43"). |
| `vendor` | string |  | Optional Vendor Class Identifier hint. |


### `prepare_distributed_configuration`

Validate a real agent/collector identity and trust configuration and produce exact net CLI argv (never a shell command). Collector clients are validated using the core enrollment parser and persisted as an owned allowlist artifact. This prepares configuration, not a running daemon or proof of connectivity; identity private keys are never included in output.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "address": {
      "type": "string"
    },
    "bpf": {
      "type": "string"
    },
    "certificate": {
      "type": "string"
    },
    "clients": {
      "type": "string"
    },
    "interface": {
      "type": "string"
    },
    "key": {
      "type": "string"
    },
    "maxConnections": {
      "type": "integer"
    },
    "maxFrameBytes": {
      "type": "integer"
    },
    "maxPendingBytes": {
      "type": "integer"
    },
    "outputDirectory": {
      "type": "string"
    },
    "role": {
      "enum": [
        "agent",
        "collector"
      ],
      "type": "string"
    },
    "serverFingerprint": {
      "type": "string"
    }
  },
  "required": [
    "role",
    "certificate",
    "key",
    "address"
  ],
  "type": "object"
}
```

### `query_audit_records`

Query one audit-record type from a session (works for ALL ~124 netcap record types, not just the ones with dedicated list_* tools). Use list_audit_records to discover what's available in the session, and get_audit_record_fields to enumerate the queryable fields of a type.

Supports the netcap filter-expression language in `filter` (an `expr`-style boolean over record fields). limit caps at 500 per call; paginate with offset.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `allow_partial` | boolean |  | Explicitly query an independently sealed audit stage even if overall analysis failed. The summary always identifies stage coverage, runId and stageGeneration. |
| `count_only` | boolean |  | If true, return only the scanned/matched counts without record bodies. |
| `fields` | string |  | Optional comma-separated top-level fields or JSON Pointer paths, e.g. Method,RequestHeader or /RequestHeaders/0/Value. Full values are preserved; oversized records provide a complete JSON artifact readable with read_mcp_artifact. |
| `filter` | string |  | Optional typed filter expression (Connection: "SrcPort == '443' && DstIP startsWith '10.'"; TCP/HTTP ports are numeric). Field names are CamelCase as in the proto schema; use get_audit_record_fields to enumerate. |
| `limit` | number |  | Maximum records to return (default 100, max 500). |
| `offset` | number |  | Offset in matching records; also supported with a filter. |
| `query_generation` | string |  | Query generation returned in summary.queryGeneration; required for partial continuation pages. |
| `run_id` | string |  | Expected capture run generation; required with allow_partial on continuation pages. |
| `session_id` | string | yes | Session identifier. |
| `stage_generation` | string |  | Stage generation returned by a partial query; required for partial continuation pages. |
| `type` | string | yes | Audit record type without NC_, e.g. DNS, HTTP, Modbus, SMB. Case-insensitive; the canonical name is returned. |


### `query_capture_catalogue`

Search 1–8 explicitly included bound finalized captures; every matching occurrence retains source/run/file/frame identity. Supported kinds sha256, domain, endpoint IP/socket, allowlisted text. Explicit tcp:// or udp:// endpoints require Connection transport evidence. First source is novelty target, remaining sources baseline. No estate scanning; overflow fails.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "type": "object",
  "properties": {
    "page": {
      "type": [
        "null",
        "object"
      ],
      "properties": {
        "offset": {
          "type": "integer"
        },
        "limit": {
          "type": "integer"
        }
      },
      "required": [
        "offset",
        "limit"
      ],
      "additionalProperties": false
    },
    "expectedSnapshotSHA256": {
      "type": "string"
    },
    "sources": {
      "type": [
        "null",
        "array"
      ],
      "items": {
        "type": "object",
        "properties": {
          "sessionId": {
            "type": "string"
          },
          "inputFile": {
            "type": "string"
          },
          "binding": {
            "type": "object",
            "properties": {
              "runId": {
                "type": "string"
              },
              "sourceSHA256": {
                "type": "string"
              },
              "manifestSHA256": {
                "type": "string"
              }
            },
            "required": [
              "runId",
              "sourceSHA256",
              "manifestSHA256"
            ],
            "additionalProperties": false
          }
        },
        "required": [
          "binding"
        ],
        "additionalProperties": false
      }
    },
    "query": {
      "type": "object",
      "properties": {
        "kind": {
          "type": "string"
        },
        "value": {
          "type": "string"
        },
        "types": {
          "type": [
            "null",
            "array"
          ],
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "kind",
        "value",
        "types"
      ],
      "additionalProperties": false
    }
  },
  "required": [
    "sources",
    "query"
  ],
  "additionalProperties": false
}
```

### `query_flow_exports`

Query one exporter/format/domain scope of normalized NetFlow/IPFIX/sFlow observations. Preserves exporter-reported counters, sampling and collection-health limitations; excludes unquantifiable/cumulative counters from additive rankings.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "domain": {
      "description": "Observation domain/source id, including zero.",
      "maximum": 4294967295,
      "minimum": 0,
      "multipleOf": 1,
      "type": "number"
    },
    "egress": {
      "description": "Exact decimal egress interface id.",
      "type": "string"
    },
    "endNs": {
      "description": "Inclusive end: exact decimal capture nanoseconds.",
      "type": "string"
    },
    "exporter": {
      "description": "Exporter IP:port (IPv6 bracketed).",
      "type": "string"
    },
    "format": {
      "description": "Export protocol.",
      "enum": [
        "netflow-v5",
        "netflow-v9",
        "ipfix",
        "sflow-v5"
      ],
      "type": "string"
    },
    "groupBy": {
      "description": "Aggregation key.",
      "enum": [
        "srcIP",
        "dstIP",
        "dstPort",
        "protocol",
        "ingress",
        "egress",
        "ingressEgress",
        "srcAS",
        "dstAS",
        "nextHop",
        "srcPrefix",
        "dstPrefix"
      ],
      "type": "string"
    },
    "host": {
      "description": "Optional IP or CIDR.",
      "type": "string"
    },
    "ingress": {
      "description": "Exact decimal ingress interface id.",
      "type": "string"
    },
    "limit": {
      "description": "Maximum groups (default 100).",
      "maximum": 500,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "nextHop": {
      "description": "Next-hop IP filter.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "startNs": {
      "description": "Inclusive start: exact decimal capture nanoseconds.",
      "type": "string"
    },
    "timeBasis": {
      "description": "Timestamp basis.",
      "enum": [
        "flow",
        "receive"
      ],
      "type": "string"
    }
  },
  "required": [
    "startNs",
    "endNs",
    "exporter",
    "format",
    "domain",
    "session_id"
  ],
  "type": "object"
}
```

### `query_flows`

Reconcile cumulative Connection snapshots before aggregation and ranking; returns source hash, observation references, statistics and coverage limitations. Whole counters overlap time windows; they are not clipped.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "bucketNs": {
      "description": "Optional exact decimal bucket width in nanoseconds.",
      "type": "string"
    },
    "endNs": {
      "description": "Inclusive end: exact decimal capture nanoseconds.",
      "type": "string"
    },
    "expectedSHA256": {
      "description": "Expected Connection audit-file SHA256, binds pages to unchanged evidence.",
      "type": "string"
    },
    "filter": {
      "description": "Connection filter expression.",
      "type": "string"
    },
    "groupBy": {
      "description": "Aggregation key.",
      "enum": [
        "srcIP",
        "dstIP",
        "dstPort",
        "protocol",
        "pair",
        "hostPair"
      ],
      "type": "string"
    },
    "limit": {
      "description": "Maximum groups (backend default 100).",
      "maximum": 500,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "offset": {
      "description": "Page offset.",
      "maximum": 10000,
      "minimum": 0,
      "multipleOf": 1,
      "type": "number"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "sortBy": {
      "description": "Ranking metric.",
      "enum": [
        "bytes",
        "packets",
        "records",
        "peers",
        "ports",
        "duration",
        "rate"
      ],
      "type": "string"
    },
    "startNs": {
      "description": "Inclusive start: exact decimal capture nanoseconds.",
      "type": "string"
    },
    "windowMode": {
      "description": "Whole-observation time selection; counters are not clipped.",
      "enum": [
        "overlap",
        "contained",
        "start",
        "end"
      ],
      "type": "string"
    }
  },
  "required": [
    "startNs",
    "endNs",
    "session_id"
  ],
  "type": "object"
}
```

### `query_timeline_events`

Read a bounded timeline event page. Preserve exact timestamp strings and occurrence references; pass generation plus returned after/before cursor to continue.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "after": {
      "description": "Forward cursor (exclusive with before).",
      "type": "string"
    },
    "before": {
      "description": "Backward cursor (exclusive with after).",
      "type": "string"
    },
    "communityId": {
      "description": "Community ID filter.",
      "type": "string"
    },
    "end": {
      "description": "Exact decimal end nanoseconds.",
      "type": "string"
    },
    "generation": {
      "description": "Generation returned by get_timeline_meta; required with cursors.",
      "type": "string"
    },
    "host": {
      "description": "Host filter.",
      "type": "string"
    },
    "limit": {
      "description": "Maximum events.",
      "maximum": 500,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "q": {
      "description": "Search text.",
      "type": "string"
    },
    "session_id": {
      "description": "Explicit session identifier returned by ingest_pcap or list_sessions.",
      "type": "string"
    },
    "start": {
      "description": "Exact decimal start nanoseconds.",
      "type": "string"
    },
    "types": {
      "description": "CSV of timeline tracks from get_timeline_meta.",
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

### `read_mcp_artifact`

Read a bounded base64 page of a retained MCP artifact/report/evidence ZIP. Use artifact_id, or the final id segment of netcap://carve/{id}. Session-derived artifacts require the original session_id. Retention is limited to 1h, 32 entries and 64 MiB of artifact bodies; content type and SHA256 identify the complete artifact.

**Hints:** read-only

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `artifact_id` | string | yes |  |
| `limit` | number |  | Page bytes, default 16384. |
| `offset` | number |  | Byte offset. |
| `session_id` | string |  |  |


### `reanalyze_session`

Create a separately retained child analysis; parent results remain available. Server-wide BPF/DPI/decoder settings apply (use set_bpf_config, set_decoder_config and set_feature before calling). Optional bounded BPF/time subsets require run_id and source_sha256 from parent provenance. Poll get_session_info with the returned child ID.

**Hints:** destructive

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `end_ns` | string |  | Inclusive end capture timestamp as an exact decimal nanosecond string; requires start_ns. |
| `max_output_bytes` | string |  | Subset output-byte limit as a decimal string; default 268435456, maximum 1073741824. |
| `max_packets` | number |  | Subset packet limit, at most 1000000. |
| `run_id` | string |  | Expected parent capture runId; required for subsets. |
| `selection_bpf` | string |  | BPF for the retained child input, e.g. host 192.0.2.10 and tcp port 9243. |
| `session_id` | string | yes | Session identifier. |
| `source_sha256` | string |  | Parent inputSHA256; required for subsets. |
| `start_ns` | string |  | Inclusive start capture timestamp as an exact decimal nanosecond string; requires end_ns. |


### `recompile_protobuf_schemas`

Recompile the configured custom Protobuf schema search paths; inspect returned status/errors before child reanalysis.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {},
  "required": [],
  "type": "object"
}
```

### `reproduce_protocol_case`

Verify generated case hash, perform declared reset and rerun its exact exchange against the explicit marker oracle.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "case": {
      "additionalProperties": false,
      "properties": {
        "configurationSHA256": {
          "type": "string"
        },
        "exchange": {
          "additionalProperties": false,
          "properties": {
            "address": {
              "type": "string"
            },
            "clientCertificateFile": {
              "type": "string"
            },
            "clientKeyFile": {
              "type": "string"
            },
            "framing": {
              "additionalProperties": false,
              "properties": {
                "byteOrder": {
                  "type": "string"
                },
                "delimiter": {
                  "contentEncoding": "base64",
                  "type": [
                    "string",
                    "null"
                  ]
                },
                "fixedSize": {
                  "type": "integer"
                },
                "kind": {
                  "type": "string"
                },
                "lengthBytes": {
                  "type": "integer"
                },
                "lengthIncludesHeader": {
                  "type": "boolean"
                },
                "maxBytes": {
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "maxBytes"
              ],
              "type": "object"
            },
            "maxTotalBytes": {
              "type": "integer"
            },
            "network": {
              "type": "string"
            },
            "peerCertificateSHA256": {
              "type": "string"
            },
            "rootCAFile": {
              "type": "string"
            },
            "serverName": {
              "type": "string"
            },
            "serverTLS": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "certificateFile": {
                      "type": "string"
                    },
                    "clientCAFile": {
                      "type": "string"
                    },
                    "keyFile": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "certificateFile",
                    "keyFile"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "steps": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "captureLength": {
                    "type": "integer"
                  },
                  "captureOffset": {
                    "type": "integer"
                  },
                  "captureVariable": {
                    "type": "string"
                  },
                  "contains": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "expect": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "expectPresent": {
                    "type": "boolean"
                  },
                  "name": {
                    "type": "string"
                  },
                  "receive": {
                    "type": "boolean"
                  },
                  "send": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "sendPresent": {
                    "type": "boolean"
                  },
                  "sendVariable": {
                    "type": "string"
                  }
                },
                "required": [
                  "name",
                  "receive"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "timeoutMilliseconds": {
              "type": "integer"
            },
            "tls": {
              "type": "boolean"
            },
            "version": {
              "type": "integer"
            }
          },
          "required": [
            "version",
            "network",
            "address",
            "tls",
            "framing",
            "timeoutMilliseconds",
            "maxTotalBytes",
            "steps"
          ],
          "type": "object"
        },
        "id": {
          "type": "string"
        },
        "kind": {
          "type": "string"
        },
        "responseStep": {
          "type": "integer"
        },
        "sendStep": {
          "type": "integer"
        }
      },
      "required": [
        "id",
        "kind",
        "exchange",
        "sendStep",
        "responseStep",
        "configurationSHA256"
      ],
      "type": "object"
    },
    "failureMarker": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "metadata": {
      "additionalProperties": false,
      "properties": {
        "reset": {
          "additionalProperties": false,
          "properties": {
            "description": {
              "type": "string"
            },
            "exchange": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "address": {
                      "type": "string"
                    },
                    "clientCertificateFile": {
                      "type": "string"
                    },
                    "clientKeyFile": {
                      "type": "string"
                    },
                    "framing": {
                      "additionalProperties": false,
                      "properties": {
                        "byteOrder": {
                          "type": "string"
                        },
                        "delimiter": {
                          "contentEncoding": "base64",
                          "type": [
                            "string",
                            "null"
                          ]
                        },
                        "fixedSize": {
                          "type": "integer"
                        },
                        "kind": {
                          "type": "string"
                        },
                        "lengthBytes": {
                          "type": "integer"
                        },
                        "lengthIncludesHeader": {
                          "type": "boolean"
                        },
                        "maxBytes": {
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "maxBytes"
                      ],
                      "type": "object"
                    },
                    "maxTotalBytes": {
                      "type": "integer"
                    },
                    "network": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    },
                    "rootCAFile": {
                      "type": "string"
                    },
                    "serverName": {
                      "type": "string"
                    },
                    "serverTLS": {
                      "anyOf": [
                        {
                          "additionalProperties": false,
                          "properties": {
                            "certificateFile": {
                              "type": "string"
                            },
                            "clientCAFile": {
                              "type": "string"
                            },
                            "keyFile": {
                              "type": "string"
                            },
                            "peerCertificateSHA256": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "certificateFile",
                            "keyFile"
                          ],
                          "type": "object"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    },
                    "steps": {
                      "items": {
                        "additionalProperties": false,
                        "properties": {
                          "captureLength": {
                            "type": "integer"
                          },
                          "captureOffset": {
                            "type": "integer"
                          },
                          "captureVariable": {
                            "type": "string"
                          },
                          "contains": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expect": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expectPresent": {
                            "type": "boolean"
                          },
                          "name": {
                            "type": "string"
                          },
                          "receive": {
                            "type": "boolean"
                          },
                          "send": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "sendPresent": {
                            "type": "boolean"
                          },
                          "sendVariable": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "name",
                          "receive"
                        ],
                        "type": "object"
                      },
                      "type": [
                        "array",
                        "null"
                      ]
                    },
                    "timeoutMilliseconds": {
                      "type": "integer"
                    },
                    "tls": {
                      "type": "boolean"
                    },
                    "version": {
                      "type": "integer"
                    }
                  },
                  "required": [
                    "version",
                    "network",
                    "address",
                    "tls",
                    "framing",
                    "timeoutMilliseconds",
                    "maxTotalBytes",
                    "steps"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "mode": {
              "type": "string"
            }
          },
          "required": [
            "mode",
            "description"
          ],
          "type": "object"
        },
        "targetVersion": {
          "type": "string"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "targetVersion",
        "reset"
      ],
      "type": "object"
    }
  },
  "required": [
    "metadata",
    "case",
    "failureMarker"
  ],
  "type": "object"
}
```

### `resolve`

Run one of netcap's local resolvers against a value: reverse DNS, GeoIP lookup, MAC vendor (OUI), IANA service-by-port, or JA4 fingerprint product mapping. All lookups are LOCAL — no outbound HTTP. Requires the netcap databases (loaded by `net dbs` or on webui startup) to be present on disk.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `kind` | string | yes | One of: dns, geoip, mac_vendor, iana_service, ja4, ja4s, ja4h, ja4x, ja4t, ja4ts, ja4tscan. |
| `protocol` | string |  | For iana_service only: "tcp" or "udp" (default tcp). |
| `value` | string | yes | Lookup key: an IP for dns/geoip, MAC for mac_vendor, port for iana_service, fingerprint hash for ja4*. |


### `resolve_audit_occurrence`

Resolve the exact original content-bound audit occurrence. Stale source, manifest, file or frame bindings fail instead of rebinding an ordinal.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "type": "object",
  "properties": {
    "source": {
      "type": "object",
      "properties": {
        "sessionId": {
          "type": "string"
        },
        "inputFile": {
          "type": "string"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        }
      },
      "required": [
        "binding"
      ],
      "additionalProperties": false
    },
    "reference": {
      "type": "object",
      "properties": {
        "version": {
          "type": "integer"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        },
        "type": {
          "type": "string"
        },
        "file": {
          "type": "string"
        },
        "fileSHA256": {
          "type": "string"
        },
        "ordinal": {
          "type": "string"
        },
        "recordSHA256": {
          "type": "string"
        },
        "timestampNs": {
          "type": "string"
        }
      },
      "required": [
        "version",
        "binding",
        "type",
        "file",
        "fileSHA256",
        "ordinal",
        "recordSHA256",
        "timestampNs"
      ],
      "additionalProperties": false
    }
  },
  "required": [
    "source",
    "reference"
  ],
  "additionalProperties": false
}
```

### `review_diagnostic_log`

Preview a finite log-line projection containing only hashes and fixed diagnostic classes, never raw log text. Explicit approve persists the exact unchanged preview. Intended for analyst review before reproduction attachment.

**Arguments (JSON Schema):**

```json
{
  "type": "object",
  "properties": {
    "source": {
      "type": "object",
      "properties": {
        "sessionId": {
          "type": "string"
        },
        "inputFile": {
          "type": "string"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        }
      },
      "required": [
        "binding"
      ],
      "additionalProperties": false
    },
    "file": {
      "type": "string"
    },
    "start": {
      "type": "integer"
    },
    "end": {
      "type": "integer"
    },
    "approve": {
      "type": [
        "null",
        "object"
      ],
      "properties": {
        "version": {
          "type": "integer"
        },
        "binding": {
          "type": "object",
          "properties": {
            "runId": {
              "type": "string"
            },
            "sourceSHA256": {
              "type": "string"
            },
            "manifestSHA256": {
              "type": "string"
            }
          },
          "required": [
            "runId",
            "sourceSHA256",
            "manifestSHA256"
          ],
          "additionalProperties": false
        },
        "file": {
          "type": "string"
        },
        "fileSHA256": {
          "type": "string"
        },
        "start": {
          "type": "integer"
        },
        "end": {
          "type": "integer"
        },
        "lines": {
          "type": [
            "null",
            "array"
          ],
          "items": {
            "type": "object",
            "properties": {
              "ordinal": {
                "type": "integer"
              },
              "sha256": {
                "type": "string"
              },
              "classes": {
                "type": [
                  "null",
                  "array"
                ],
                "items": {
                  "type": "string"
                }
              }
            },
            "required": [
              "ordinal",
              "sha256",
              "classes"
            ],
            "additionalProperties": false
          }
        },
        "projectionSHA256": {
          "type": "string"
        },
        "state": {
          "type": "string"
        }
      },
      "required": [
        "version",
        "binding",
        "file",
        "fileSHA256",
        "start",
        "end",
        "lines",
        "projectionSHA256",
        "state"
      ],
      "additionalProperties": false
    }
  },
  "required": [
    "source",
    "file",
    "start",
    "end"
  ],
  "additionalProperties": false
}
```

### `run_protocol_access_matrix`

Run labeled state/role/resource cases with a new session and declared reset per case. Missing markers are meaningful only after response assertions match; transport failures stay inconclusive.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "cases": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "allowed": {
            "type": "boolean"
          },
          "exchange": {
            "additionalProperties": false,
            "properties": {
              "address": {
                "type": "string"
              },
              "clientCertificateFile": {
                "type": "string"
              },
              "clientKeyFile": {
                "type": "string"
              },
              "framing": {
                "additionalProperties": false,
                "properties": {
                  "byteOrder": {
                    "type": "string"
                  },
                  "delimiter": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "fixedSize": {
                    "type": "integer"
                  },
                  "kind": {
                    "type": "string"
                  },
                  "lengthBytes": {
                    "type": "integer"
                  },
                  "lengthIncludesHeader": {
                    "type": "boolean"
                  },
                  "maxBytes": {
                    "type": "integer"
                  }
                },
                "required": [
                  "kind",
                  "maxBytes"
                ],
                "type": "object"
              },
              "maxTotalBytes": {
                "type": "integer"
              },
              "network": {
                "type": "string"
              },
              "peerCertificateSHA256": {
                "type": "string"
              },
              "rootCAFile": {
                "type": "string"
              },
              "serverName": {
                "type": "string"
              },
              "serverTLS": {
                "anyOf": [
                  {
                    "additionalProperties": false,
                    "properties": {
                      "certificateFile": {
                        "type": "string"
                      },
                      "clientCAFile": {
                        "type": "string"
                      },
                      "keyFile": {
                        "type": "string"
                      },
                      "peerCertificateSHA256": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "certificateFile",
                      "keyFile"
                    ],
                    "type": "object"
                  },
                  {
                    "type": "null"
                  }
                ]
              },
              "steps": {
                "items": {
                  "additionalProperties": false,
                  "properties": {
                    "captureLength": {
                      "type": "integer"
                    },
                    "captureOffset": {
                      "type": "integer"
                    },
                    "captureVariable": {
                      "type": "string"
                    },
                    "contains": {
                      "contentEncoding": "base64",
                      "type": [
                        "string",
                        "null"
                      ]
                    },
                    "expect": {
                      "contentEncoding": "base64",
                      "type": [
                        "string",
                        "null"
                      ]
                    },
                    "expectPresent": {
                      "type": "boolean"
                    },
                    "name": {
                      "type": "string"
                    },
                    "receive": {
                      "type": "boolean"
                    },
                    "send": {
                      "contentEncoding": "base64",
                      "type": [
                        "string",
                        "null"
                      ]
                    },
                    "sendPresent": {
                      "type": "boolean"
                    },
                    "sendVariable": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "name",
                    "receive"
                  ],
                  "type": "object"
                },
                "type": [
                  "array",
                  "null"
                ]
              },
              "timeoutMilliseconds": {
                "type": "integer"
              },
              "tls": {
                "type": "boolean"
              },
              "version": {
                "type": "integer"
              }
            },
            "required": [
              "version",
              "network",
              "address",
              "tls",
              "framing",
              "timeoutMilliseconds",
              "maxTotalBytes",
              "steps"
            ],
            "type": "object"
          },
          "marker": {
            "contentEncoding": "base64",
            "type": [
              "string",
              "null"
            ]
          },
          "message": {
            "type": "string"
          },
          "metadata": {
            "additionalProperties": false,
            "properties": {
              "reset": {
                "additionalProperties": false,
                "properties": {
                  "description": {
                    "type": "string"
                  },
                  "exchange": {
                    "anyOf": [
                      {
                        "additionalProperties": false,
                        "properties": {
                          "address": {
                            "type": "string"
                          },
                          "clientCertificateFile": {
                            "type": "string"
                          },
                          "clientKeyFile": {
                            "type": "string"
                          },
                          "framing": {
                            "additionalProperties": false,
                            "properties": {
                              "byteOrder": {
                                "type": "string"
                              },
                              "delimiter": {
                                "contentEncoding": "base64",
                                "type": [
                                  "string",
                                  "null"
                                ]
                              },
                              "fixedSize": {
                                "type": "integer"
                              },
                              "kind": {
                                "type": "string"
                              },
                              "lengthBytes": {
                                "type": "integer"
                              },
                              "lengthIncludesHeader": {
                                "type": "boolean"
                              },
                              "maxBytes": {
                                "type": "integer"
                              }
                            },
                            "required": [
                              "kind",
                              "maxBytes"
                            ],
                            "type": "object"
                          },
                          "maxTotalBytes": {
                            "type": "integer"
                          },
                          "network": {
                            "type": "string"
                          },
                          "peerCertificateSHA256": {
                            "type": "string"
                          },
                          "rootCAFile": {
                            "type": "string"
                          },
                          "serverName": {
                            "type": "string"
                          },
                          "serverTLS": {
                            "anyOf": [
                              {
                                "additionalProperties": false,
                                "properties": {
                                  "certificateFile": {
                                    "type": "string"
                                  },
                                  "clientCAFile": {
                                    "type": "string"
                                  },
                                  "keyFile": {
                                    "type": "string"
                                  },
                                  "peerCertificateSHA256": {
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "certificateFile",
                                  "keyFile"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "steps": {
                            "items": {
                              "additionalProperties": false,
                              "properties": {
                                "captureLength": {
                                  "type": "integer"
                                },
                                "captureOffset": {
                                  "type": "integer"
                                },
                                "captureVariable": {
                                  "type": "string"
                                },
                                "contains": {
                                  "contentEncoding": "base64",
                                  "type": [
                                    "string",
                                    "null"
                                  ]
                                },
                                "expect": {
                                  "contentEncoding": "base64",
                                  "type": [
                                    "string",
                                    "null"
                                  ]
                                },
                                "expectPresent": {
                                  "type": "boolean"
                                },
                                "name": {
                                  "type": "string"
                                },
                                "receive": {
                                  "type": "boolean"
                                },
                                "send": {
                                  "contentEncoding": "base64",
                                  "type": [
                                    "string",
                                    "null"
                                  ]
                                },
                                "sendPresent": {
                                  "type": "boolean"
                                },
                                "sendVariable": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "name",
                                "receive"
                              ],
                              "type": "object"
                            },
                            "type": [
                              "array",
                              "null"
                            ]
                          },
                          "timeoutMilliseconds": {
                            "type": "integer"
                          },
                          "tls": {
                            "type": "boolean"
                          },
                          "version": {
                            "type": "integer"
                          }
                        },
                        "required": [
                          "version",
                          "network",
                          "address",
                          "tls",
                          "framing",
                          "timeoutMilliseconds",
                          "maxTotalBytes",
                          "steps"
                        ],
                        "type": "object"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "mode": {
                    "type": "string"
                  }
                },
                "required": [
                  "mode",
                  "description"
                ],
                "type": "object"
              },
              "targetVersion": {
                "type": "string"
              },
              "version": {
                "type": "integer"
              }
            },
            "required": [
              "version",
              "targetVersion",
              "reset"
            ],
            "type": "object"
          },
          "resource": {
            "type": "string"
          },
          "responseStep": {
            "type": "integer"
          },
          "role": {
            "type": "string"
          },
          "state": {
            "type": "string"
          }
        },
        "required": [
          "metadata",
          "responseStep",
          "role",
          "state",
          "resource",
          "message",
          "allowed",
          "marker",
          "exchange"
        ],
        "type": "object"
      },
      "type": [
        "array",
        "null"
      ]
    }
  },
  "required": [
    "cases"
  ],
  "type": "object"
}
```

### `run_protocol_boundary`

Compare valid control/probe/readback across a semantic boundary using exact accepted/rejected replies; preserve harness-error and qualification states.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "accepted": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "control": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "type": "string"
        },
        "clientCertificateFile": {
          "type": "string"
        },
        "clientKeyFile": {
          "type": "string"
        },
        "framing": {
          "additionalProperties": false,
          "properties": {
            "byteOrder": {
              "type": "string"
            },
            "delimiter": {
              "contentEncoding": "base64",
              "type": [
                "string",
                "null"
              ]
            },
            "fixedSize": {
              "type": "integer"
            },
            "kind": {
              "type": "string"
            },
            "lengthBytes": {
              "type": "integer"
            },
            "lengthIncludesHeader": {
              "type": "boolean"
            },
            "maxBytes": {
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "maxBytes"
          ],
          "type": "object"
        },
        "maxTotalBytes": {
          "type": "integer"
        },
        "network": {
          "type": "string"
        },
        "peerCertificateSHA256": {
          "type": "string"
        },
        "rootCAFile": {
          "type": "string"
        },
        "serverName": {
          "type": "string"
        },
        "serverTLS": {
          "anyOf": [
            {
              "additionalProperties": false,
              "properties": {
                "certificateFile": {
                  "type": "string"
                },
                "clientCAFile": {
                  "type": "string"
                },
                "keyFile": {
                  "type": "string"
                },
                "peerCertificateSHA256": {
                  "type": "string"
                }
              },
              "required": [
                "certificateFile",
                "keyFile"
              ],
              "type": "object"
            },
            {
              "type": "null"
            }
          ]
        },
        "steps": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "captureLength": {
                "type": "integer"
              },
              "captureOffset": {
                "type": "integer"
              },
              "captureVariable": {
                "type": "string"
              },
              "contains": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expect": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expectPresent": {
                "type": "boolean"
              },
              "name": {
                "type": "string"
              },
              "receive": {
                "type": "boolean"
              },
              "send": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "sendPresent": {
                "type": "boolean"
              },
              "sendVariable": {
                "type": "string"
              }
            },
            "required": [
              "name",
              "receive"
            ],
            "type": "object"
          },
          "type": [
            "array",
            "null"
          ]
        },
        "timeoutMilliseconds": {
          "type": "integer"
        },
        "tls": {
          "type": "boolean"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "network",
        "address",
        "tls",
        "framing",
        "timeoutMilliseconds",
        "maxTotalBytes",
        "steps"
      ],
      "type": "object"
    },
    "metadata": {
      "additionalProperties": false,
      "properties": {
        "reset": {
          "additionalProperties": false,
          "properties": {
            "description": {
              "type": "string"
            },
            "exchange": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "address": {
                      "type": "string"
                    },
                    "clientCertificateFile": {
                      "type": "string"
                    },
                    "clientKeyFile": {
                      "type": "string"
                    },
                    "framing": {
                      "additionalProperties": false,
                      "properties": {
                        "byteOrder": {
                          "type": "string"
                        },
                        "delimiter": {
                          "contentEncoding": "base64",
                          "type": [
                            "string",
                            "null"
                          ]
                        },
                        "fixedSize": {
                          "type": "integer"
                        },
                        "kind": {
                          "type": "string"
                        },
                        "lengthBytes": {
                          "type": "integer"
                        },
                        "lengthIncludesHeader": {
                          "type": "boolean"
                        },
                        "maxBytes": {
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "maxBytes"
                      ],
                      "type": "object"
                    },
                    "maxTotalBytes": {
                      "type": "integer"
                    },
                    "network": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    },
                    "rootCAFile": {
                      "type": "string"
                    },
                    "serverName": {
                      "type": "string"
                    },
                    "serverTLS": {
                      "anyOf": [
                        {
                          "additionalProperties": false,
                          "properties": {
                            "certificateFile": {
                              "type": "string"
                            },
                            "clientCAFile": {
                              "type": "string"
                            },
                            "keyFile": {
                              "type": "string"
                            },
                            "peerCertificateSHA256": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "certificateFile",
                            "keyFile"
                          ],
                          "type": "object"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    },
                    "steps": {
                      "items": {
                        "additionalProperties": false,
                        "properties": {
                          "captureLength": {
                            "type": "integer"
                          },
                          "captureOffset": {
                            "type": "integer"
                          },
                          "captureVariable": {
                            "type": "string"
                          },
                          "contains": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expect": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expectPresent": {
                            "type": "boolean"
                          },
                          "name": {
                            "type": "string"
                          },
                          "receive": {
                            "type": "boolean"
                          },
                          "send": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "sendPresent": {
                            "type": "boolean"
                          },
                          "sendVariable": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "name",
                          "receive"
                        ],
                        "type": "object"
                      },
                      "type": [
                        "array",
                        "null"
                      ]
                    },
                    "timeoutMilliseconds": {
                      "type": "integer"
                    },
                    "tls": {
                      "type": "boolean"
                    },
                    "version": {
                      "type": "integer"
                    }
                  },
                  "required": [
                    "version",
                    "network",
                    "address",
                    "tls",
                    "framing",
                    "timeoutMilliseconds",
                    "maxTotalBytes",
                    "steps"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "mode": {
              "type": "string"
            }
          },
          "required": [
            "mode",
            "description"
          ],
          "type": "object"
        },
        "targetVersion": {
          "type": "string"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "targetVersion",
        "reset"
      ],
      "type": "object"
    },
    "name": {
      "type": "string"
    },
    "probe": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "type": "string"
        },
        "clientCertificateFile": {
          "type": "string"
        },
        "clientKeyFile": {
          "type": "string"
        },
        "framing": {
          "additionalProperties": false,
          "properties": {
            "byteOrder": {
              "type": "string"
            },
            "delimiter": {
              "contentEncoding": "base64",
              "type": [
                "string",
                "null"
              ]
            },
            "fixedSize": {
              "type": "integer"
            },
            "kind": {
              "type": "string"
            },
            "lengthBytes": {
              "type": "integer"
            },
            "lengthIncludesHeader": {
              "type": "boolean"
            },
            "maxBytes": {
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "maxBytes"
          ],
          "type": "object"
        },
        "maxTotalBytes": {
          "type": "integer"
        },
        "network": {
          "type": "string"
        },
        "peerCertificateSHA256": {
          "type": "string"
        },
        "rootCAFile": {
          "type": "string"
        },
        "serverName": {
          "type": "string"
        },
        "serverTLS": {
          "anyOf": [
            {
              "additionalProperties": false,
              "properties": {
                "certificateFile": {
                  "type": "string"
                },
                "clientCAFile": {
                  "type": "string"
                },
                "keyFile": {
                  "type": "string"
                },
                "peerCertificateSHA256": {
                  "type": "string"
                }
              },
              "required": [
                "certificateFile",
                "keyFile"
              ],
              "type": "object"
            },
            {
              "type": "null"
            }
          ]
        },
        "steps": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "captureLength": {
                "type": "integer"
              },
              "captureOffset": {
                "type": "integer"
              },
              "captureVariable": {
                "type": "string"
              },
              "contains": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expect": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expectPresent": {
                "type": "boolean"
              },
              "name": {
                "type": "string"
              },
              "receive": {
                "type": "boolean"
              },
              "send": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "sendPresent": {
                "type": "boolean"
              },
              "sendVariable": {
                "type": "string"
              }
            },
            "required": [
              "name",
              "receive"
            ],
            "type": "object"
          },
          "type": [
            "array",
            "null"
          ]
        },
        "timeoutMilliseconds": {
          "type": "integer"
        },
        "tls": {
          "type": "boolean"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "network",
        "address",
        "tls",
        "framing",
        "timeoutMilliseconds",
        "maxTotalBytes",
        "steps"
      ],
      "type": "object"
    },
    "rejected": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "responseStep": {
      "type": "integer"
    },
    "verification": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "address": {
              "type": "string"
            },
            "clientCertificateFile": {
              "type": "string"
            },
            "clientKeyFile": {
              "type": "string"
            },
            "framing": {
              "additionalProperties": false,
              "properties": {
                "byteOrder": {
                  "type": "string"
                },
                "delimiter": {
                  "contentEncoding": "base64",
                  "type": [
                    "string",
                    "null"
                  ]
                },
                "fixedSize": {
                  "type": "integer"
                },
                "kind": {
                  "type": "string"
                },
                "lengthBytes": {
                  "type": "integer"
                },
                "lengthIncludesHeader": {
                  "type": "boolean"
                },
                "maxBytes": {
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "maxBytes"
              ],
              "type": "object"
            },
            "maxTotalBytes": {
              "type": "integer"
            },
            "network": {
              "type": "string"
            },
            "peerCertificateSHA256": {
              "type": "string"
            },
            "rootCAFile": {
              "type": "string"
            },
            "serverName": {
              "type": "string"
            },
            "serverTLS": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "certificateFile": {
                      "type": "string"
                    },
                    "clientCAFile": {
                      "type": "string"
                    },
                    "keyFile": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "certificateFile",
                    "keyFile"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "steps": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "captureLength": {
                    "type": "integer"
                  },
                  "captureOffset": {
                    "type": "integer"
                  },
                  "captureVariable": {
                    "type": "string"
                  },
                  "contains": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "expect": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "expectPresent": {
                    "type": "boolean"
                  },
                  "name": {
                    "type": "string"
                  },
                  "receive": {
                    "type": "boolean"
                  },
                  "send": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "sendPresent": {
                    "type": "boolean"
                  },
                  "sendVariable": {
                    "type": "string"
                  }
                },
                "required": [
                  "name",
                  "receive"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "timeoutMilliseconds": {
              "type": "integer"
            },
            "tls": {
              "type": "boolean"
            },
            "version": {
              "type": "integer"
            }
          },
          "required": [
            "version",
            "network",
            "address",
            "tls",
            "framing",
            "timeoutMilliseconds",
            "maxTotalBytes",
            "steps"
          ],
          "type": "object"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "metadata",
    "name",
    "control",
    "probe",
    "responseStep",
    "accepted",
    "rejected"
  ],
  "type": "object"
}
```

### `run_protocol_campaign`

Run bounded deterministic mutations and minimization with valid pre/post controls, explicit reset isolation and response marker oracle. Timeout/crash is not RCE; partial failures remain report errors.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "control": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "type": "string"
        },
        "clientCertificateFile": {
          "type": "string"
        },
        "clientKeyFile": {
          "type": "string"
        },
        "framing": {
          "additionalProperties": false,
          "properties": {
            "byteOrder": {
              "type": "string"
            },
            "delimiter": {
              "contentEncoding": "base64",
              "type": [
                "string",
                "null"
              ]
            },
            "fixedSize": {
              "type": "integer"
            },
            "kind": {
              "type": "string"
            },
            "lengthBytes": {
              "type": "integer"
            },
            "lengthIncludesHeader": {
              "type": "boolean"
            },
            "maxBytes": {
              "type": "integer"
            }
          },
          "required": [
            "kind",
            "maxBytes"
          ],
          "type": "object"
        },
        "maxTotalBytes": {
          "type": "integer"
        },
        "network": {
          "type": "string"
        },
        "peerCertificateSHA256": {
          "type": "string"
        },
        "rootCAFile": {
          "type": "string"
        },
        "serverName": {
          "type": "string"
        },
        "serverTLS": {
          "anyOf": [
            {
              "additionalProperties": false,
              "properties": {
                "certificateFile": {
                  "type": "string"
                },
                "clientCAFile": {
                  "type": "string"
                },
                "keyFile": {
                  "type": "string"
                },
                "peerCertificateSHA256": {
                  "type": "string"
                }
              },
              "required": [
                "certificateFile",
                "keyFile"
              ],
              "type": "object"
            },
            {
              "type": "null"
            }
          ]
        },
        "steps": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "captureLength": {
                "type": "integer"
              },
              "captureOffset": {
                "type": "integer"
              },
              "captureVariable": {
                "type": "string"
              },
              "contains": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expect": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "expectPresent": {
                "type": "boolean"
              },
              "name": {
                "type": "string"
              },
              "receive": {
                "type": "boolean"
              },
              "send": {
                "contentEncoding": "base64",
                "type": [
                  "string",
                  "null"
                ]
              },
              "sendPresent": {
                "type": "boolean"
              },
              "sendVariable": {
                "type": "string"
              }
            },
            "required": [
              "name",
              "receive"
            ],
            "type": "object"
          },
          "type": [
            "array",
            "null"
          ]
        },
        "timeoutMilliseconds": {
          "type": "integer"
        },
        "tls": {
          "type": "boolean"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "network",
        "address",
        "tls",
        "framing",
        "timeoutMilliseconds",
        "maxTotalBytes",
        "steps"
      ],
      "type": "object"
    },
    "failureMarker": {
      "contentEncoding": "base64",
      "type": [
        "string",
        "null"
      ]
    },
    "generation": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "buildSeed": {
              "type": "boolean"
            },
            "bytes": {
              "type": "boolean"
            },
            "fields": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "name": {
                    "type": "string"
                  },
                  "values": {
                    "items": {
                      "contentEncoding": "base64",
                      "type": [
                        "string",
                        "null"
                      ]
                    },
                    "type": [
                      "array",
                      "null"
                    ]
                  }
                },
                "required": [
                  "name"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "grammar": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "fields": {
                      "items": {
                        "additionalProperties": false,
                        "properties": {
                          "byteOrder": {
                            "type": "string"
                          },
                          "expected": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "hypothesis": {
                            "type": "string"
                          },
                          "kind": {
                            "type": "string"
                          },
                          "length": {
                            "type": "integer"
                          },
                          "lengthFrom": {
                            "anyOf": [
                              {
                                "additionalProperties": false,
                                "properties": {
                                  "adjustment": {
                                    "type": "integer"
                                  },
                                  "byteOrder": {
                                    "type": "string"
                                  },
                                  "offset": {
                                    "type": "integer"
                                  },
                                  "width": {
                                    "type": "integer"
                                  }
                                },
                                "required": [
                                  "offset",
                                  "width",
                                  "byteOrder",
                                  "adjustment"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "name": {
                            "type": "string"
                          },
                          "offset": {
                            "type": "integer"
                          },
                          "tlv": {
                            "anyOf": [
                              {
                                "additionalProperties": false,
                                "properties": {
                                  "byteOrder": {
                                    "type": "string"
                                  },
                                  "leafKind": {
                                    "type": "string"
                                  },
                                  "lengthBytes": {
                                    "type": "integer"
                                  },
                                  "lengthIncludesHeader": {
                                    "type": "boolean"
                                  },
                                  "maxDepth": {
                                    "type": "integer"
                                  },
                                  "maxEntries": {
                                    "type": "integer"
                                  },
                                  "maxValueBytes": {
                                    "type": "integer"
                                  },
                                  "nestedTypes": {
                                    "items": {
                                      "minimum": 0,
                                      "type": "integer"
                                    },
                                    "type": [
                                      "array",
                                      "null"
                                    ]
                                  },
                                  "typeBytes": {
                                    "type": "integer"
                                  }
                                },
                                "required": [
                                  "typeBytes",
                                  "lengthBytes",
                                  "byteOrder",
                                  "lengthIncludesHeader",
                                  "leafKind",
                                  "maxDepth",
                                  "maxEntries",
                                  "maxValueBytes"
                                ],
                                "type": "object"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          }
                        },
                        "required": [
                          "name",
                          "offset",
                          "length",
                          "kind",
                          "hypothesis"
                        ],
                        "type": "object"
                      },
                      "type": [
                        "array",
                        "null"
                      ]
                    },
                    "framing": {
                      "additionalProperties": false,
                      "properties": {
                        "byteOrder": {
                          "type": "string"
                        },
                        "delimiter": {
                          "contentEncoding": "base64",
                          "type": [
                            "string",
                            "null"
                          ]
                        },
                        "fixedSize": {
                          "type": "integer"
                        },
                        "kind": {
                          "type": "string"
                        },
                        "lengthBytes": {
                          "type": "integer"
                        },
                        "lengthIncludesHeader": {
                          "type": "boolean"
                        },
                        "maxBytes": {
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "maxBytes"
                      ],
                      "type": "object"
                    },
                    "maxFrames": {
                      "type": "integer"
                    },
                    "version": {
                      "type": "integer"
                    }
                  },
                  "required": [
                    "version",
                    "framing",
                    "fields",
                    "maxFrames"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "states": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "action": {
                    "type": "string"
                  },
                  "step": {
                    "type": "integer"
                  }
                },
                "required": [
                  "action",
                  "step"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "version": {
              "type": "integer"
            }
          },
          "required": [
            "version",
            "bytes",
            "buildSeed"
          ],
          "type": "object"
        },
        {
          "type": "null"
        }
      ]
    },
    "maxAttempts": {
      "type": "integer"
    },
    "maxCases": {
      "type": "integer"
    },
    "metadata": {
      "additionalProperties": false,
      "properties": {
        "reset": {
          "additionalProperties": false,
          "properties": {
            "description": {
              "type": "string"
            },
            "exchange": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "address": {
                      "type": "string"
                    },
                    "clientCertificateFile": {
                      "type": "string"
                    },
                    "clientKeyFile": {
                      "type": "string"
                    },
                    "framing": {
                      "additionalProperties": false,
                      "properties": {
                        "byteOrder": {
                          "type": "string"
                        },
                        "delimiter": {
                          "contentEncoding": "base64",
                          "type": [
                            "string",
                            "null"
                          ]
                        },
                        "fixedSize": {
                          "type": "integer"
                        },
                        "kind": {
                          "type": "string"
                        },
                        "lengthBytes": {
                          "type": "integer"
                        },
                        "lengthIncludesHeader": {
                          "type": "boolean"
                        },
                        "maxBytes": {
                          "type": "integer"
                        }
                      },
                      "required": [
                        "kind",
                        "maxBytes"
                      ],
                      "type": "object"
                    },
                    "maxTotalBytes": {
                      "type": "integer"
                    },
                    "network": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    },
                    "rootCAFile": {
                      "type": "string"
                    },
                    "serverName": {
                      "type": "string"
                    },
                    "serverTLS": {
                      "anyOf": [
                        {
                          "additionalProperties": false,
                          "properties": {
                            "certificateFile": {
                              "type": "string"
                            },
                            "clientCAFile": {
                              "type": "string"
                            },
                            "keyFile": {
                              "type": "string"
                            },
                            "peerCertificateSHA256": {
                              "type": "string"
                            }
                          },
                          "required": [
                            "certificateFile",
                            "keyFile"
                          ],
                          "type": "object"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    },
                    "steps": {
                      "items": {
                        "additionalProperties": false,
                        "properties": {
                          "captureLength": {
                            "type": "integer"
                          },
                          "captureOffset": {
                            "type": "integer"
                          },
                          "captureVariable": {
                            "type": "string"
                          },
                          "contains": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expect": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "expectPresent": {
                            "type": "boolean"
                          },
                          "name": {
                            "type": "string"
                          },
                          "receive": {
                            "type": "boolean"
                          },
                          "send": {
                            "contentEncoding": "base64",
                            "type": [
                              "string",
                              "null"
                            ]
                          },
                          "sendPresent": {
                            "type": "boolean"
                          },
                          "sendVariable": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "name",
                          "receive"
                        ],
                        "type": "object"
                      },
                      "type": [
                        "array",
                        "null"
                      ]
                    },
                    "timeoutMilliseconds": {
                      "type": "integer"
                    },
                    "tls": {
                      "type": "boolean"
                    },
                    "version": {
                      "type": "integer"
                    }
                  },
                  "required": [
                    "version",
                    "network",
                    "address",
                    "tls",
                    "framing",
                    "timeoutMilliseconds",
                    "maxTotalBytes",
                    "steps"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "mode": {
              "type": "string"
            }
          },
          "required": [
            "mode",
            "description"
          ],
          "type": "object"
        },
        "targetVersion": {
          "type": "string"
        },
        "version": {
          "type": "integer"
        }
      },
      "required": [
        "version",
        "targetVersion",
        "reset"
      ],
      "type": "object"
    },
    "responseStep": {
      "type": "integer"
    },
    "sendStep": {
      "type": "integer"
    }
  },
  "required": [
    "metadata",
    "control",
    "sendStep",
    "responseStep",
    "failureMarker",
    "maxCases",
    "maxAttempts"
  ],
  "type": "object"
}
```

### `run_protocol_exchange`

Run one bounded TCP/UDP/TLS exchange with framing, response assertions, fresh variables and exact byte/hash observations. Byte fields are base64. Uses existing network policy; no shell commands or automatic interpretation of payload instructions.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "address": {
      "type": "string"
    },
    "clientCertificateFile": {
      "type": "string"
    },
    "clientKeyFile": {
      "type": "string"
    },
    "framing": {
      "additionalProperties": false,
      "properties": {
        "byteOrder": {
          "type": "string"
        },
        "delimiter": {
          "contentEncoding": "base64",
          "type": [
            "string",
            "null"
          ]
        },
        "fixedSize": {
          "type": "integer"
        },
        "kind": {
          "type": "string"
        },
        "lengthBytes": {
          "type": "integer"
        },
        "lengthIncludesHeader": {
          "type": "boolean"
        },
        "maxBytes": {
          "type": "integer"
        }
      },
      "required": [
        "kind",
        "maxBytes"
      ],
      "type": "object"
    },
    "maxTotalBytes": {
      "type": "integer"
    },
    "network": {
      "type": "string"
    },
    "peerCertificateSHA256": {
      "type": "string"
    },
    "rootCAFile": {
      "type": "string"
    },
    "serverName": {
      "type": "string"
    },
    "serverTLS": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "certificateFile": {
              "type": "string"
            },
            "clientCAFile": {
              "type": "string"
            },
            "keyFile": {
              "type": "string"
            },
            "peerCertificateSHA256": {
              "type": "string"
            }
          },
          "required": [
            "certificateFile",
            "keyFile"
          ],
          "type": "object"
        },
        {
          "type": "null"
        }
      ]
    },
    "steps": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "captureLength": {
            "type": "integer"
          },
          "captureOffset": {
            "type": "integer"
          },
          "captureVariable": {
            "type": "string"
          },
          "contains": {
            "contentEncoding": "base64",
            "type": [
              "string",
              "null"
            ]
          },
          "expect": {
            "contentEncoding": "base64",
            "type": [
              "string",
              "null"
            ]
          },
          "expectPresent": {
            "type": "boolean"
          },
          "name": {
            "type": "string"
          },
          "receive": {
            "type": "boolean"
          },
          "send": {
            "contentEncoding": "base64",
            "type": [
              "string",
              "null"
            ]
          },
          "sendPresent": {
            "type": "boolean"
          },
          "sendVariable": {
            "type": "string"
          }
        },
        "required": [
          "name",
          "receive"
        ],
        "type": "object"
      },
      "type": [
        "array",
        "null"
      ]
    },
    "timeoutMilliseconds": {
      "type": "integer"
    },
    "tls": {
      "type": "boolean"
    },
    "version": {
      "maximum": 9007199254740991,
      "type": "integer"
    }
  },
  "required": [
    "version",
    "network",
    "address",
    "tls",
    "framing",
    "timeoutMilliseconds",
    "maxTotalBytes",
    "steps"
  ],
  "type": "object"
}
```

### `sensor_bundle`

Use a named operator-enrolled sensor authority. seal requires explicit session_id/run_id and optionally shorter retention; import accepts a bundle_id in the enrolled inbox/sealed namespace OR an owned sensor-bundle artifact_id; export returns a bounded signed ZIP artifact; list/prune act only within enrollment. No per-call keys, identities, paths or namespaces are accepted. HMAC proves shared-key possession, not endpoint authentication.

**Hints:** destructive

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "artifact_id": {
      "type": "string"
    },
    "binding": {
      "type": "string"
    },
    "bundle_id": {
      "type": "string"
    },
    "limit": {
      "type": "integer"
    },
    "offset": {
      "type": "integer"
    },
    "operation": {
      "enum": [
        "list",
        "seal",
        "import",
        "export",
        "prune"
      ],
      "type": "string"
    },
    "retention_seconds": {
      "type": "integer"
    },
    "run_id": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "stage": {
      "enum": [
        "sealed",
        "imports",
        "inbox"
      ],
      "type": "string"
    }
  },
  "required": [
    "operation",
    "binding"
  ],
  "type": "object"
}
```

### `set_analysis_settings`

Patch actual future-analysis settings without resetting omitted fields. False and empty CSV values are honored; null/unknown settings are rejected. Changes reach subsequent helper jobs and retained child reanalysis. Component limits exclude RSS; unavailable DPI cannot be enabled. Read get_analysis_settings first.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "captureTimeIdleExpiry": {
      "type": "boolean"
    },
    "dpi": {
      "type": "boolean"
    },
    "dpiModules": {
      "description": "CSV go,ndpi,lpi; empty selects defaults.",
      "type": "string"
    },
    "flowExportPorts": {
      "description": "Observed UDP port CSV; empty selects defaults.",
      "type": "string"
    },
    "flowExports": {
      "type": "boolean"
    },
    "incrementalHTTP": {
      "type": "boolean"
    },
    "maxAggregateStateBytes": {
      "description": "Aggregate state budget.",
      "maximum": 1073741824,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "maxReassemblyBytes": {
      "description": "Aggregate reassembly page budget.",
      "maximum": 4294967296,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "maxTCPBytes": {
      "description": "Copied TCP payload budget across workers.",
      "maximum": 1073741824,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "maxTCPStateBytes": {
      "description": "TCP parser state budget.",
      "maximum": 1073741824,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "payload": {
      "type": "boolean"
    },
    "retainPackets": {
      "type": "boolean"
    },
    "retentionMB": {
      "description": "Packet budget MiB; at least one segment.",
      "maximum": 16384,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "segmentMB": {
      "description": "Packet segment MiB.",
      "maximum": 1024,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    }
  },
  "required": [],
  "type": "object"
}
```

### `set_bpf_config`

Validate and persist a process-wide BPF filter for future analyses (including child reanalysis). Empty filter clears it; does not change existing results.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "filter": {
      "description": "BPF expression, or empty to clear.",
      "type": "string"
    }
  },
  "required": [
    "filter"
  ],
  "type": "object"
}
```

### `set_decoder_config`

Replace process-wide decoder selection for future analyses. Supply both includeDecoders and excludeDecoders (CSV); empty strings reset to all. Discover valid names with list_decoders.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "excludeDecoders": {
      "description": "Excluded decoder CSV, or empty.",
      "type": "string"
    },
    "includeDecoders": {
      "description": "Exclusive decoder CSV, or empty.",
      "type": "string"
    }
  },
  "required": [
    "includeDecoders",
    "excludeDecoders"
  ],
  "type": "object"
}
```

### `set_feature`

Toggle one process-wide optional feature. evidence-links applies to the next query; capture-scoped changes reach subsequent in-process and helper analyses, including child reanalysis. Existing results remain unchanged. Read get_features first.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "enabled": {
      "type": "boolean"
    },
    "name": {
      "description": "Feature name.",
      "enum": [
        "network-detection",
        "evidence-links",
        "dns-resolution-context"
      ],
      "type": "string"
    }
  },
  "required": [
    "name",
    "enabled"
  ],
  "type": "object"
}
```

### `set_protobuf_mapping`

Map a port to a loaded custom Protobuf message type. Paths/mappings/preferences reach subsequent analyses and retained child reanalysis, including helper processes. Existing results remain unchanged; inspect get_protobuf_status for compile status.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "messageType": {
      "description": "Fully qualified loaded message type.",
      "type": "string"
    },
    "port": {
      "description": "TCP/UDP port.",
      "maximum": 65535,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    }
  },
  "required": [
    "port",
    "messageType"
  ],
  "type": "object"
}
```

### `start_live_capture`

Start one owned bounded local-host capture. Requires an existing interface, durationSeconds 1..300, retentionMB 1..512. Returns session_id; poll get_live_capture_status and stop_live_capture with that ID. Promiscuous mode is disabled. Hosted service mode cannot mix host traffic into tenant captures.

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "bpf": {
      "description": "Optional BPF.",
      "type": "string"
    },
    "durationSeconds": {
      "description": "Maximum duration.",
      "maximum": 300,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    },
    "interface": {
      "description": "Interface from list_network_interfaces.",
      "type": "string"
    },
    "retentionMB": {
      "description": "Rotating packet disk budget in MiB; additional audit output has a maintenance-time guard.",
      "maximum": 512,
      "minimum": 1,
      "multipleOf": 1,
      "type": "number"
    }
  },
  "required": [
    "interface",
    "durationSeconds",
    "retentionMB"
  ],
  "type": "object"
}
```

### `start_protocol_listener`

Start one bounded loopback TCP/TLS/peer-pinned UDP emulation or TCP/TLS application/passthrough proxy. Requires mode server + exchange OR mode proxy + proxy, and literal loopback listen address (port 0 supported). Returns job_id and actual address before waiting for a peer. Poll get_protocol_job; stop_protocol_job cancels. Maximum 8 retained jobs, 5 minutes each; byte fields are base64.

**Hints:** open-world

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "exchange": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "address": {
              "type": "string"
            },
            "clientCertificateFile": {
              "type": "string"
            },
            "clientKeyFile": {
              "type": "string"
            },
            "framing": {
              "additionalProperties": false,
              "properties": {
                "byteOrder": {
                  "type": "string"
                },
                "delimiter": {
                  "contentEncoding": "base64",
                  "type": [
                    "string",
                    "null"
                  ]
                },
                "fixedSize": {
                  "type": "integer"
                },
                "kind": {
                  "type": "string"
                },
                "lengthBytes": {
                  "type": "integer"
                },
                "lengthIncludesHeader": {
                  "type": "boolean"
                },
                "maxBytes": {
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "maxBytes"
              ],
              "type": "object"
            },
            "maxTotalBytes": {
              "type": "integer"
            },
            "network": {
              "type": "string"
            },
            "peerCertificateSHA256": {
              "type": "string"
            },
            "rootCAFile": {
              "type": "string"
            },
            "serverName": {
              "type": "string"
            },
            "serverTLS": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "certificateFile": {
                      "type": "string"
                    },
                    "clientCAFile": {
                      "type": "string"
                    },
                    "keyFile": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "certificateFile",
                    "keyFile"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            },
            "steps": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "captureLength": {
                    "type": "integer"
                  },
                  "captureOffset": {
                    "type": "integer"
                  },
                  "captureVariable": {
                    "type": "string"
                  },
                  "contains": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "expect": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "expectPresent": {
                    "type": "boolean"
                  },
                  "name": {
                    "type": "string"
                  },
                  "receive": {
                    "type": "boolean"
                  },
                  "send": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "sendPresent": {
                    "type": "boolean"
                  },
                  "sendVariable": {
                    "type": "string"
                  }
                },
                "required": [
                  "name",
                  "receive"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "timeoutMilliseconds": {
              "type": "integer"
            },
            "tls": {
              "type": "boolean"
            },
            "version": {
              "type": "integer"
            }
          },
          "required": [
            "version",
            "network",
            "address",
            "tls",
            "framing",
            "timeoutMilliseconds",
            "maxTotalBytes",
            "steps"
          ],
          "type": "object"
        },
        {
          "type": "null"
        }
      ]
    },
    "listen": {
      "type": "string"
    },
    "mode": {
      "enum": [
        "server",
        "proxy"
      ],
      "type": "string"
    },
    "proxy": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "address": {
              "type": "string"
            },
            "framing": {
              "additionalProperties": false,
              "properties": {
                "byteOrder": {
                  "type": "string"
                },
                "delimiter": {
                  "contentEncoding": "base64",
                  "type": [
                    "string",
                    "null"
                  ]
                },
                "fixedSize": {
                  "type": "integer"
                },
                "kind": {
                  "type": "string"
                },
                "lengthBytes": {
                  "type": "integer"
                },
                "lengthIncludesHeader": {
                  "type": "boolean"
                },
                "maxBytes": {
                  "type": "integer"
                }
              },
              "required": [
                "kind",
                "maxBytes"
              ],
              "type": "object"
            },
            "injections": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "beforeFrame": {
                    "type": "integer"
                  },
                  "direction": {
                    "type": "string"
                  },
                  "message": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  }
                },
                "required": [
                  "direction",
                  "beforeFrame",
                  "message"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "maxFrames": {
              "type": "integer"
            },
            "maxTotalBytes": {
              "type": "integer"
            },
            "mode": {
              "type": "string"
            },
            "mutations": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "copies": {
                    "type": "integer"
                  },
                  "delayMilliseconds": {
                    "type": "integer"
                  },
                  "delete": {
                    "type": "integer"
                  },
                  "direction": {
                    "type": "string"
                  },
                  "drop": {
                    "type": "boolean"
                  },
                  "frame": {
                    "type": "integer"
                  },
                  "insert": {
                    "contentEncoding": "base64",
                    "type": [
                      "string",
                      "null"
                    ]
                  },
                  "offset": {
                    "type": "integer"
                  },
                  "repairLength": {
                    "type": "boolean"
                  }
                },
                "required": [
                  "direction",
                  "frame",
                  "offset",
                  "delete",
                  "insert",
                  "repairLength",
                  "drop",
                  "copies",
                  "delayMilliseconds"
                ],
                "type": "object"
              },
              "type": [
                "array",
                "null"
              ]
            },
            "timeoutMilliseconds": {
              "type": "integer"
            },
            "tls": {
              "anyOf": [
                {
                  "additionalProperties": false,
                  "properties": {
                    "certificateFile": {
                      "type": "string"
                    },
                    "clientCertificateFile": {
                      "type": "string"
                    },
                    "clientKeyFile": {
                      "type": "string"
                    },
                    "keyFile": {
                      "type": "string"
                    },
                    "mode": {
                      "type": "string"
                    },
                    "peerCertificateSHA256": {
                      "type": "string"
                    },
                    "rootCAFile": {
                      "type": "string"
                    },
                    "serverName": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "certificateFile",
                    "keyFile",
                    "rootCAFile",
                    "serverName"
                  ],
                  "type": "object"
                },
                {
                  "type": "null"
                }
              ]
            }
          },
          "required": [
            "address",
            "framing",
            "timeoutMilliseconds",
            "maxFrames",
            "maxTotalBytes",
            "mutations"
          ],
          "type": "object"
        },
        {
          "type": "null"
        }
      ]
    }
  },
  "required": [
    "mode",
    "listen"
  ],
  "type": "object"
}
```

### `stop_live_capture`

Stop an in-progress live capture on the netcap webui host. Returns immediately; ongoing audit-record processing continues until the existing buffers drain. No-op (and returns an error) if the webui isn't currently in live-capture mode.

**Hints:** destructive, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `session_id` | string |  | Owned capture ID; when supplied a different session cannot be stopped. |


### `stop_protocol_job`

Cancel one owned protocol listener/proxy by job_id; poll get_protocol_job for final partial evidence.

**Hints:** destructive, open-world

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `job_id` | string | yes |  |


### `validate_offline_rule_pack`

Parse and validate inline netcap-offline-rules/v1 YAML without executing it or changing captures.

**Hints:** read-only

**Arguments (JSON Schema):**

```json
{
  "additionalProperties": false,
  "properties": {
    "yaml": {
      "description": "Complete offline rule pack YAML.",
      "type": "string"
    }
  },
  "required": [
    "yaml"
  ],
  "type": "object"
}
```

### `wait_for_session`

Poll get_session_info server-side until the session is completed or the timeout elapses. Returns the final session_info payload verbatim (so the LLM can read it without an extra round-trip). Spares the LLM from burning conversation turns on polling loops.

**Hints:** read-only, idempotent

**Arguments:**

| name | type | required | description |
| --- | --- | --- | --- |
| `poll_interval_ms` | number |  | How frequently to poll (default 500, min 100, max 5000). |
| `session_id` | string | yes | Session identifier. |
| `timeout_seconds` | number |  | Maximum time to wait (default 60, max 300). |


