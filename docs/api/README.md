# Backend REST API Reference

> **Status**: Initial inventory — audit and full request/response schemas to be added.
> Tracked in [#226](https://github.com/NotYuSheng/TracePcap/issues/226).

## Base URL

All endpoints are prefixed with `/api/v1`.

---

## Files — `/api/v1/files`

Controllers: `FileController`, `ReportController`, `SecurityAlertsController`, `HostClassificationsController`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/files` | Upload a PCAP file (multipart/form-data) |
| `GET` | `/api/v1/files` | List all uploaded files |
| `GET` | `/api/v1/files/{fileId}` | Get metadata for a single file |
| `GET` | `/api/v1/files/{fileId}/download` | Download the raw PCAP file |
| `DELETE` | `/api/v1/files/{fileId}` | Delete a file |
| `POST` | `/api/v1/files/merge` | Merge multiple PCAP files |
| `POST` | `/api/v1/files/{fileId}/report` | Generate a report for a file |
| `POST` | `/api/v1/files/compare/report` | Generate a comparison report |
| `GET` | `/api/v1/files/{fileId}/security-alerts` | Get security alerts for a file |
| `GET` | `/api/v1/files/{fileId}/host-classifications` | Get host classifications for a file |

---

## Conversations — `/api/v1/conversations`

Controller: `ConversationsController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/conversations/{fileId}` | List conversations for a file (supports filters) |
| `GET` | `/api/v1/conversations/{fileId}/file-types` | Get distinct file types in conversations |
| `GET` | `/api/v1/conversations/{fileId}/risk-types` | Get distinct risk types |
| `GET` | `/api/v1/conversations/{fileId}/custom-signatures` | Get custom signature hits |
| `GET` | `/api/v1/conversations/{fileId}/countries` | Get countries involved in conversations |
| `GET` | `/api/v1/conversations/{fileId}/export` | Export conversations as CSV/JSON |
| `GET` | `/api/v1/conversations/{fileId}/export-pcap` | Export filtered conversations as PCAP |
| `GET` | `/api/v1/conversations/{conversationId}/session` | Get session data for a conversation |
| `GET` | `/api/v1/conversations/detail/{conversationId}` | Get full detail for a single conversation |
| `GET` | `/api/v1/conversations/detail/{conversationId}/export-pcap` | Export a single conversation as PCAP |

---

## Analysis — `/api/v1/analysis`

Controller: `AnalysisController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/analysis/{fileId}/summary` | Get analysis summary for a file |
| `GET` | `/api/v1/analysis/{fileId}/protocols` | Get protocol breakdown for a file |

---

## Timeline — `/api/v1/timeline`

Controller: `TimelineController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/timeline/{fileId}` | Get timeline events for a file |
| `GET` | `/api/v1/timeline/{fileId}/range` | Get timeline events within a time range |

---

## Extracted Files — `/api/v1/files/{fileId}/extractions`

Controller: `ExtractedFilesController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/files/{fileId}/extractions` | List extracted files from a PCAP |
| `GET` | `/api/v1/files/{fileId}/extractions/{extractionId}/download` | Download an extracted file |

---

## Signatures — `/api/v1/signatures`

Controller: `SignaturesController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/signatures` | List all signatures |
| `GET` | `/api/v1/signatures/rules` | Get signature rules |
| `PUT` | `/api/v1/signatures` | Update signatures |

---

## Story — `/api/v1/story`

Controller: `StoryController`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/story/generate/{fileId}` | Generate an AI story for a file |
| `GET` | `/api/v1/story/{storyId}` | Get a story by ID |
| `POST` | `/api/v1/story/{storyId}/ask` | Ask a follow-up question on a story |
| `GET` | `/api/v1/story/file/{fileId}` | Get story for a file |

---

## Conversation Tracer — `/api/v1/tracer`

Controller: `ConversationTracerController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/tracer/{conversationId}/steps` | Get trace steps for a conversation |
| `GET` | `/api/v1/tracer/{conversationId}/peers` | List the host's peers, each flagged as responded or silent |
| `POST` | `/api/v1/tracer/{conversationId}/explain` | Generate LLM explanation for a conversation |

---

## Network Intelligence — `/api/v1/network/intelligence`

Controller: `NetworkIntelligenceController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/network/intelligence/{fileId}/clusters` | Get network clusters for a file |
| `GET` | `/api/v1/network/intelligence/{fileId}/top-hosts` | Get top hosts by traffic volume |

---

## IP Org Rules — `/api/v1/ip-org-rules`

Controller: `IpOrgRuleController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/ip-org-rules` | List all IP-to-org mapping rules |
| `POST` | `/api/v1/ip-org-rules` | Create a new rule |
| `DELETE` | `/api/v1/ip-org-rules/{id}` | Delete a rule |

---

## Filter — `/api/v1/filter`

Controller: `FilterController`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/filter/generate/{fileId}` | Generate a display filter for a file |
| `POST` | `/api/v1/filter/execute/{fileId}` | Execute a filter on a file |

---

## System — `/api/v1/system`

Controller: `SystemController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/system/limits` | Get system resource limits |

---

## Network Monitor & related

The Network Monitor endpoints — networks, snapshots, change events, baseline
definitions, subnets (`/api/v1/subnets`), node roles (`/api/v1/node-roles`),
entity notes (`/api/v1/entity-notes`), external events, analyst annotations,
insights, and private-range overrides (`/api/v1/custom-private-ranges`) — are
documented with full request/response details in the Sphinx docs:
[Network Monitor → REST API Reference](../features/network-monitor.rst).
