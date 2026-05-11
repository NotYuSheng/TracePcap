# Backend REST API Reference

> **Status**: Initial inventory — audit and full request/response schemas to be added.
> Tracked in [#226](https://github.com/NotYuSheng/TracePcap/issues/226).

## Base URL

All endpoints are prefixed with `/api`.

---

## Files — `/api/files`

Controllers: `FileController`, `ReportController`, `SecurityAlertsController`, `HostClassificationsController`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/files` | Upload a PCAP file (multipart/form-data) |
| `GET` | `/api/files` | List all uploaded files |
| `GET` | `/api/files/{fileId}` | Get metadata for a single file |
| `GET` | `/api/files/{fileId}/download` | Download the raw PCAP file |
| `DELETE` | `/api/files/{fileId}` | Delete a file |
| `POST` | `/api/files/merge` | Merge multiple PCAP files |
| `POST` | `/api/files/{fileId}/report` | Generate a report for a file |
| `POST` | `/api/files/compare/report` | Generate a comparison report |
| `GET` | `/api/files/{fileId}/security-alerts` | Get security alerts for a file |
| `GET` | `/api/files/{fileId}/host-classifications` | Get host classifications for a file |

---

## Conversations — `/api/conversations`

Controller: `ConversationsController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/conversations/{fileId}` | List conversations for a file (supports filters) |
| `GET` | `/api/conversations/{fileId}/file-types` | Get distinct file types in conversations |
| `GET` | `/api/conversations/{fileId}/risk-types` | Get distinct risk types |
| `GET` | `/api/conversations/{fileId}/custom-signatures` | Get custom signature hits |
| `GET` | `/api/conversations/{fileId}/countries` | Get countries involved in conversations |
| `GET` | `/api/conversations/{fileId}/export` | Export conversations as CSV/JSON |
| `GET` | `/api/conversations/{fileId}/export-pcap` | Export filtered conversations as PCAP |
| `GET` | `/api/conversations/{conversationId}/session` | Get session data for a conversation |
| `GET` | `/api/conversations/detail/{conversationId}` | Get full detail for a single conversation |
| `GET` | `/api/conversations/detail/{conversationId}/export-pcap` | Export a single conversation as PCAP |

---

## Analysis — `/api/analysis`

Controller: `AnalysisController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/analysis/{fileId}/summary` | Get analysis summary for a file |
| `GET` | `/api/analysis/{fileId}/protocols` | Get protocol breakdown for a file |

---

## Timeline — `/api/timeline`

Controller: `TimelineController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/timeline/{fileId}` | Get timeline events for a file |
| `GET` | `/api/timeline/{fileId}/range` | Get timeline events within a time range |

---

## Extracted Files — `/api/files/{fileId}/extractions`

Controller: `ExtractedFilesController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/files/{fileId}/extractions` | List extracted files from a PCAP |
| `GET` | `/api/files/{fileId}/extractions/{extractionId}/download` | Download an extracted file |

---

## Signatures — `/api/signatures`

Controller: `SignaturesController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/signatures` | List all signatures |
| `GET` | `/api/signatures/rules` | Get signature rules |
| `PUT` | `/api/signatures` | Update signatures |

---

## Story — `/api/story`

Controller: `StoryController`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/story/generate/{fileId}` | Generate an AI story for a file |
| `GET` | `/api/story/{storyId}` | Get a story by ID |
| `POST` | `/api/story/{storyId}/ask` | Ask a follow-up question on a story |
| `GET` | `/api/story/file/{fileId}` | Get story for a file |

---

## Conversation Tracer — `/api/tracer`

Controller: `ConversationTracerController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/tracer/{conversationId}/steps` | Get trace steps for a conversation |
| `POST` | `/api/tracer/{conversationId}/explain` | Generate LLM explanation for a conversation |

---

## Network Intelligence — `/api/network/intelligence`

Controller: `NetworkIntelligenceController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/network/intelligence/{fileId}/clusters` | Get network clusters for a file |
| `GET` | `/api/network/intelligence/{fileId}/top-hosts` | Get top hosts by traffic volume |

---

## IP Org Rules — `/api/ip-org-rules`

Controller: `IpOrgRuleController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/ip-org-rules` | List all IP-to-org mapping rules |
| `POST` | `/api/ip-org-rules` | Create a new rule |
| `DELETE` | `/api/ip-org-rules/{id}` | Delete a rule |

---

## Filter — `/api/filter`

Controller: `FilterController`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/filter/generate/{fileId}` | Generate a display filter for a file |
| `POST` | `/api/filter/execute/{fileId}` | Execute a filter on a file |

---

## System — `/api/system`

Controller: `SystemController`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/system/limits` | Get system resource limits |
