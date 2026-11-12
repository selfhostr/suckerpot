# Event schema

Every sensor sends the same shape of event. The model is `Event` in the `suckerpot-common` package (`sensors/common`). It is a Pydantic model with `frozen=True` and `extra="forbid"`. Unknown fields are rejected.

## Fields

| Field | Type | Constraints | Content |
| --- | --- | --- | --- |
| `ts` | datetime | Must include a time zone. Stored in UTC. | When the attacker did it |
| `sensor` | enum | `ssh`, `telnet`, `adb`, `web`, `docker`, `redis`, `mysql`, `mssql`, `rdp`, `smb`, `sip`, `synology` | Which sensor saw it |
| `session_id` | string | 1 to 64 characters, `A-Z a-z 0-9 _ -` only | Groups all events of one connection |
| `src_ip` | IP address | IPv4 or IPv6 | Attacker address |
| `src_port` | integer | 0 to 65535 | Attacker port |
| `dst_port` | integer | 0 to 65535 | Port the attacker connected to |
| `type` | enum | See below | What happened |
| `data` | object | JSON-serializable. At most 16 KiB once serialized. | Details, as JSON. Keys depend on `type`. |

### Event types

| `type` | Meaning |
| --- | --- |
| `connect` | A connection opened |
| `login_attempt` | A login was tried, successful or not |
| `command` | A command was typed in a fake shell |
| `http_request` | An HTTP request was received |
| `download_attempt` | A download command was seen (for example `wget`). The URL is recorded, the file is not fetched. |
| `disconnect` | The connection closed |
| `scan` | A probe seen by a sensor, for example a port scan |

## Recommended `data` keys

The `data` object is free-form, but sensors should use these keys. The tagging rules (M4) depend on them.

| `type` | Keys |
| --- | --- |
| `login_attempt` | `username`, `password`, `success` (boolean), `method` (`password`, `publickey` or `keyboard-interactive` for SSH and Telnet; `rdp-cookie`, `rdp-ntlm` or `rdp-nla-off` for RDP) |

### Synology DSM keys

The Synology sensor sends HTTP requests, so its `http_request` events carry the usual HTTP keys. On top of them it sets these keys.

| Key | Content |
| --- | --- |
| `api`, `api_method`, `api_version` | The DSM Web API call, for example `SYNO.API.Auth`, `login`, version 6. |
| `flags` | The request shapes the sensor saw, such as `dsm_api`, `sid_forge` or `ransom_indicator`. See the [Synology sensor](sensors/synology.md#flags). |
| `cve` | `["CVE-2026-13639", "CVE-2026-13684"]`, only with `sid_forge` or `scgi_injection`. |

### RDP login methods

The RDP sensor uses three login methods. Each one carries different fields, and the password is only ever set in the last two cases.

| `method` | When it happens | Password | Extra fields |
| --- | --- | --- | --- |
| `rdp-cookie` | The client sent a `mstshash` user name in the connection request | Always null | `client_tool`, `requested_protocols`, `routing_token` and others |
| `rdp-ntlm` | The client completed an NTLM exchange (NLA) | Set only for a configured decoy account whose password matched. Otherwise null. | `domain`, `workstation`, `ntlm_version` (`v1` or `v2`), `nt_response_len`, `nt_response_preview` (8 bytes) |
| `rdp-nla-off` | The client skipped NLA and sent its password in the Client Info PDU. Only with `RDP_NLA_MODE=optional`. | Cleartext, length-limited | `domain`, `alternate_shell`, `working_dir`, `client_tool` |

The full RDP field list is in [RDP sensor](sensors/rdp.md#what-it-records).
| `command` | `input` (string), `output_preview` (string, optional) |
| `download_attempt` | `url`, `tool` (`wget`, `curl`, `tftp` and so on), `command` |
| `http_request` | `method`, `path`, `query`, `headers` (object), `user_agent`, `body_preview`, `status` |
| `connect` | `client_version` (optional) |
| `disconnect` | `duration_s`, `reason` |
| `scan` | `payload_preview` (hex string) |

### Size limits

| Limit | Value | What happens when it is exceeded |
| --- | --- | --- |
| Serialized `data` | 16 KiB | The event is rejected by validation |
| Raw `event` field in a stream entry | 64 KiB | Rejected before the JSON is parsed |

Sensors must cut attacker-controlled text before they build an event. The helper `truncate_data()` in `suckerpot-common` does this. It caps each string and the total size of `data`, and it cuts keys to a fixed length. Use it on every field that comes from the attacker.

## Example

An SSH login attempt, with documentation addresses only:

```json
{
  "ts": "2026-10-24T18:02:11Z",
  "sensor": "ssh",
  "session_id": "k3J9x2_a7Qe",
  "src_ip": "198.51.100.23",
  "src_port": 51422,
  "dst_port": 22,
  "type": "login_attempt",
  "data": {
    "username": "root",
    "password": "123456",
    "success": false,
    "method": "password"
  }
}
```

## Stream encoding

Each sensor has its own Redis stream: `events:ssh`, `events:telnet`, `events:adb`, `events:web`, `events:docker`, `events:redis`, `events:mysql`, `events:mssql`, `events:rdp`, `events:smb`, `events:sip` and `events:synology`. Each event is one entry in the stream of the sensor that produced it. The `sensor` field of the event must match the stream suffix, or ingest drops the event. The entry has two fields:

| Field | Value |
| --- | --- |
| `v` | Schema version. Currently `"1"`. |
| `event` | The event as a JSON string |

The publisher writes the entry with `XADD`, with an approximate length cap set by `EVENTS_MAXLEN` (default 10,000):

```text
XADD events:ssh MAXLEN ~ 10000 * v 1 event '{"ts":"2026-10-24T18:02:11Z", ...}'
```

A reader checks `v` first. It rejects any version it does not know. Then it validates the JSON with the same model.

## Publishing failures

The publisher never raises an error into the sensor, because an attacker-facing handler must not crash or hang when the queue is unhealthy. If Redis refuses the write (for example when memory is full), the event is dropped and counted. The error is logged at most once every 30 seconds per error kind. There is no internal buffer.

## Validation failures

`ingest` does not stop on a bad entry. An entry that fails validation is logged, with the content truncated, and then acknowledged. This keeps the stream moving. A bad entry is never written to the database.

If the database rejects a batch, ingest retries it with a backoff. A single message that still fails after 5 attempts is logged with its stream ID and acknowledged, so it is dead-lettered.

## Session fields

Ingest groups events by `session_id` into the `sessions` table. A session keeps its first and last times, the number of events, and counters such as `login_attempts`, `login_success`, `commands`, `downloads` and `http_requests`. Enrichment and tags are added to both events and sessions (M4).

A `session_id` that starts with `burst-` is reserved: it names a flood group, a `sessions` row that stands for many plain connections of one source (see [Data retention](retention.md#flood-groups)). A sensor must never produce one, and ingest drops any event that carries one.

A session also has `client_tool`, a best-effort guess at the software that connected (for example `FreeRDP`, `nmap` or `mstsc`). Only the RDP sensor sets it, from the `client_tool` value in its events. `unknown` and other sensors' values are stored as null. The guess is never authoritative. See [Client tool identification](sensors/rdp.md#client-tool-identification).
