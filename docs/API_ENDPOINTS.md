# TracePcap Backend API Endpoints

## Base URL
```
http://localhost:8080/api
```

## Architecture Overview

**Storage Layer:**
- **MinIO**: Object storage for PCAP files (`tracepcap-files` bucket)
- **PostgreSQL**: Metadata, analysis results, conversations, and timeline data

**Upload Flow:**
```
Client → Spring Boot → MinIO (file storage)
              ↓
         PostgreSQL (metadata)
              ↓
      Async Analysis Worker
              ↓
         PostgreSQL (results)
```

**File Lifecycle:**
1. Client uploads PCAP file via `POST /api/files`
2. Backend validates file (type, size, format)
3. Backend uploads to MinIO: `s3://tracepcap-files/{fileId}.pcap`
4. Backend saves metadata to PostgreSQL
5. Backend triggers async analysis job
6. Analysis worker reads file from MinIO
7. Analysis results stored in PostgreSQL
8. File remains in MinIO for future re-analysis

**MinIO Configuration:**
```yaml
minio:
  endpoint: http://localhost:9000
  access-key: minioadmin
  secret-key: minioadmin
  bucket: tracepcap-files
  max-file-size: 104857600  # 100MB
  retention-days: 90  # Auto-delete after 90 days
```

## 1. File Management

### Upload PCAP File
```http
POST /api/files
Content-Type: multipart/form-data

Request Body:
- file: <binary PCAP file>

Response: 201 Created
{
  "fileId": "uuid-v4",
  "fileName": "capture.pcap",
  "fileSize": 1048576,
  "uploadedAt": 1738368000000,
  "status": "processing",
  "storageLocation": "s3://tracepcap-files/uuid-v4.pcap"
}

Backend Processing:
1. Validates file extension (.pcap, .pcapng, .cap)
2. Validates file size (max 100MB)
3. Validates PCAP file format (magic bytes)
4. Generates UUID for fileId
5. Uploads to MinIO: tracepcap-files/{fileId}.pcap
6. Saves metadata to PostgreSQL files table
7. Triggers async analysis job
8. Returns 201 with file metadata
```

### Get All Files
```http
GET /api/files
Query Parameters:
- page: number (default: 0)
- size: number (default: 20)
- sort: string (default: "uploadedAt,desc")

Response: 200 OK
{
  "content": [
    {
      "fileId": "uuid-v4",
      "fileName": "capture.pcap",
      "fileSize": 1048576,
      "uploadedAt": 1738368000000,
      "status": "completed"
    }
  ],
  "page": 0,
  "size": 20,
  "totalElements": 1,
  "totalPages": 1
}
```

### Get File Metadata
```http
GET /api/files/{fileId}

Response: 200 OK
{
  "fileId": "uuid-v4",
  "fileName": "capture.pcap",
  "fileSize": 1048576,
  "uploadedAt": 1738368000000,
  "status": "completed",
  "packetCount": 125432,
  "duration": 3300000,
  "startTime": 1738364700000,
  "endTime": 1738368000000
}
```

### Delete File
```http
DELETE /api/files/{fileId}

Response: 204 No Content

Backend Processing:
1. Deletes file from MinIO: tracepcap-files/{fileId}.pcap
2. Deletes metadata from PostgreSQL files table
3. Deletes associated analysis data (cascading delete)
4. Deletes conversations, timeline, and story data
5. Returns 204 No Content

Note: This is a hard delete. Consider implementing soft delete with retention policy.
```

### Download PCAP File
```http
GET /api/files/{fileId}/download

Response: 200 OK
Content-Type: application/vnd.tcpdump.pcap
Content-Disposition: attachment; filename="capture.pcap"

<binary PCAP file data>

Backend Processing:
1. Retrieves file metadata from PostgreSQL
2. Generates pre-signed URL from MinIO (valid for 5 minutes)
3. Streams file from MinIO to client
4. Sets appropriate headers for browser download
```

## 2. Analysis

### Get Analysis Summary
```http
GET /api/files/{fileId}/analysis

Response: 200 OK
{
  "fileId": "uuid-v4",
  "fileName": "capture.pcap",
  "fileSize": 1048576,
  "uploadedAt": 1738368000000,
  "packetCount": 125432,
  "totalBytes": 87654321,
  "duration": 3300000,
  "uniqueHosts": 6,
  "conversationCount": 8,
  "protocolCount": 7,
  "startTime": 1738364700000,
  "endTime": 1738368000000,
  "protocolDistribution": [
    {
      "name": "HTTP",
      "count": 45000,
      "bytes": 32000000,
      "percentage": 0.36
    },
    {
      "name": "TCP",
      "count": 38000,
      "bytes": 27000000,
      "percentage": 0.30
    }
  ],
  "topConversations": [
    {
      "source": "192.168.1.100:52341",
      "destination": "93.184.216.34:443",
      "protocol": "HTTPS",
      "packets": 8934,
      "bytes": 4567890
    }
  ],
  "hosts": [
    {
      "ip": "192.168.1.100",
      "hostname": "client-device.local",
      "packetsSent": 62716,
      "packetsReceived": 62716,
      "bytesSent": 43827160,
      "bytesReceived": 43827161
    }
  ]
}
```

### Get Protocol Statistics
```http
GET /api/files/{fileId}/analysis/protocols

Response: 200 OK
[
  {
    "name": "HTTP",
    "count": 45000,
    "bytes": 32000000,
    "percentage": 0.36
  },
  {
    "name": "TCP",
    "count": 38000,
    "bytes": 27000000,
    "percentage": 0.30
  }
]
```

### Get Five W's Analysis
```http
GET /api/files/{fileId}/analysis/fivews

Response: 200 OK
{
  "who": {
    "hosts": [
      {
        "ip": "192.168.1.100",
        "hostname": "client-device.local",
        "role": "client",
        "activity": "high"
      }
    ],
    "summary": "Primary communication involves 6 unique hosts..."
  },
  "what": {
    "protocols": ["HTTP", "HTTPS", "DNS", "TCP"],
    "activities": ["Web browsing", "API communication", "DNS resolution"],
    "summary": "Network activity consists primarily of web traffic..."
  },
  "when": {
    "startTime": 1738364700000,
    "endTime": 1738368000000,
    "duration": 3300000,
    "peakTime": 1738366500000,
    "summary": "Capture spans 55 minutes with peak activity at 14:35..."
  },
  "where": {
    "sourceNetworks": ["192.168.1.0/24"],
    "destinationNetworks": ["93.184.216.0/24", "172.217.14.0/24"],
    "geographicLocations": ["United States", "Singapore"],
    "summary": "Traffic originates from local network 192.168.1.0/24..."
  },
  "why": {
    "purpose": "Enterprise network activity",
    "patterns": ["Regular API polling", "Content delivery", "DNS lookups"],
    "anomalies": ["Port scanning detected", "Unusual data volume"],
    "summary": "Network behavior suggests normal enterprise operations..."
  }
}
```

## 3. Conversations

### Get All Conversations
```http
GET /api/files/{fileId}/conversations
Query Parameters:
- page: number (default: 0)
- size: number (default: 50)
- protocol: string (optional filter)
- sortBy: string (default: "packetCount,desc")

Response: 200 OK
{
  "content": [
    {
      "id": "conv-uuid-1",
      "endpoints": [
        {
          "ip": "192.168.1.100",
          "port": 52341,
          "hostname": "client-device.local"
        },
        {
          "ip": "93.184.216.34",
          "port": 443,
          "hostname": "api.example.com"
        }
      ],
      "protocol": {
        "layer": "application",
        "name": "HTTPS"
      },
      "startTime": 1738365200000,
      "endTime": 1738368100000,
      "packetCount": 8934,
      "totalBytes": 4567890,
      "direction": "bidirectional"
    }
  ],
  "page": 0,
  "size": 50,
  "totalElements": 8,
  "totalPages": 1
}
```

### Get Conversation Details
```http
GET /api/conversations/{conversationId}
Query Parameters:
- includePackets: boolean (default: true)
- packetLimit: number (default: 100)

Response: 200 OK
{
  "id": "conv-uuid-1",
  "endpoints": [
    {
      "ip": "192.168.1.100",
      "port": 52341,
      "hostname": "client-device.local"
    },
    {
      "ip": "93.184.216.34",
      "port": 443,
      "hostname": "api.example.com"
    }
  ],
  "protocol": {
    "layer": "application",
    "name": "HTTPS"
  },
  "startTime": 1738365200000,
  "endTime": 1738368100000,
  "packetCount": 8934,
  "totalBytes": 4567890,
  "direction": "bidirectional",
  "packets": [
    {
      "id": "pkt-uuid-1",
      "timestamp": 1738365200123,
      "source": {
        "ip": "192.168.1.100",
        "port": 52341
      },
      "destination": {
        "ip": "93.184.216.34",
        "port": 443
      },
      "protocol": {
        "layer": "application",
        "name": "HTTPS"
      },
      "size": 1420,
      "flags": ["ACK", "PSH"],
      "payload": "base64-encoded-payload"
    }
  ]
}
```

### Get Sessions (Grouped Conversations)
```http
GET /api/files/{fileId}/sessions

Response: 200 OK
[
  {
    "id": "session-uuid-1",
    "name": "HTTPS Session - api.example.com",
    "protocol": "HTTPS",
    "startTime": 1738365200000,
    "endTime": 1738368100000,
    "conversationIds": ["conv-uuid-1", "conv-uuid-2"],
    "totalPackets": 9500,
    "totalBytes": 5000000
  }
]
```

## 4. Timeline

### Get Timeline Data
```http
GET /api/files/{fileId}/timeline
Query Parameters:
- interval: number (milliseconds, default: 60000)
- startTime: number (optional)
- endTime: number (optional)

Response: 200 OK
[
  {
    "timestamp": 1738364700000,
    "packetCount": 2500,
    "bytes": 1800000,
    "protocols": {
      "HTTP": 900,
      "TCP": 750,
      "UDP": 500,
      "DNS": 200,
      "TLS": 100,
      "Other": 50
    }
  },
  {
    "timestamp": 1738364760000,
    "packetCount": 2800,
    "bytes": 2000000,
    "protocols": {
      "HTTP": 1000,
      "TCP": 800,
      "UDP": 550,
      "DNS": 250,
      "TLS": 150,
      "Other": 50
    }
  }
]
```

### Get Timeline Range
```http
GET /api/files/{fileId}/timeline/range
Query Parameters:
- startTime: number (required)
- endTime: number (required)
- interval: number (milliseconds, default: 60000)

Response: 200 OK
[
  {
    "timestamp": 1738364700000,
    "packetCount": 2500,
    "bytes": 1800000,
    "protocols": {
      "HTTP": 900,
      "TCP": 750,
      "UDP": 500,
      "DNS": 200,
      "TLS": 100,
      "Other": 50
    }
  }
]
```

## 5. Story / Narrative

### Generate Story
```http
POST /api/files/{fileId}/story

Response: 202 Accepted
{
  "storyId": "story-uuid-1",
  "fileId": "uuid-v4",
  "status": "generating",
  "generatedAt": 1738368000000
}

Note: Story generation is async. Poll GET /api/stories/{storyId} for completion.
```

### Get Story Status
```http
GET /api/stories/{storyId}

Response: 200 OK
{
  "id": "story-uuid-1",
  "fileId": "uuid-v4",
  "status": "completed",
  "generatedAt": 1738368000000,
  "narrative": [
    {
      "title": "Executive Summary",
      "content": "This network capture reveals typical enterprise...",
      "type": "summary",
      "relatedData": {
        "hosts": ["192.168.1.100", "93.184.216.34"],
        "conversations": ["conv-uuid-1"],
        "packets": []
      }
    }
  ],
  "highlights": [
    {
      "id": "highlight-uuid-1",
      "type": "anomaly",
      "title": "Port Scanning Detected",
      "description": "Sequential port scan detected from client device...",
      "timestamp": 1738366000000
    }
  ],
  "timeline": [
    {
      "timestamp": 1738364700000,
      "title": "Capture Started",
      "description": "Network capture initiated, initial DNS queries observed",
      "type": "normal",
      "relatedData": {
        "conversations": ["conv-uuid-2"]
      }
    }
  ]
}
```

### Get Story by File ID
```http
GET /api/files/{fileId}/story

Response: 200 OK
{
  "id": "story-uuid-1",
  "fileId": "uuid-v4",
  "status": "completed",
  "generatedAt": 1738368000000,
  "narrative": [...],
  "highlights": [...],
  "timeline": [...]
}

Note: Returns 404 if no story exists for this file.
```

## 6. Health & Status

### Health Check
```http
GET /api/health

Response: 200 OK
{
  "status": "UP",
  "timestamp": 1738368000000,
  "version": "1.0.0"
}
```

### Get Processing Status
```http
GET /api/files/{fileId}/status

Response: 200 OK
{
  "fileId": "uuid-v4",
  "status": "processing",
  "progress": 45,
  "currentStep": "Analyzing conversations",
  "estimatedCompletion": 1738368060000
}
```

## Error Responses

### Common Error Format
```json
{
  "timestamp": 1738368000000,
  "status": 400,
  "error": "Bad Request",
  "message": "Invalid file format. Only .pcap, .pcapng, and .cap files are supported.",
  "path": "/api/files"
}
```

### HTTP Status Codes
- `200 OK` - Successful GET request
- `201 Created` - Successful POST request (resource created)
- `202 Accepted` - Request accepted for async processing
- `204 No Content` - Successful DELETE request
- `400 Bad Request` - Invalid request parameters
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict (e.g., duplicate upload)
- `413 Payload Too Large` - File size exceeds limit
- `415 Unsupported Media Type` - Invalid file type
- `422 Unprocessable Entity` - Invalid PCAP file content
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Server overloaded/maintenance

## Request Headers

### Required Headers
```http
Content-Type: application/json (for JSON requests)
Content-Type: multipart/form-data (for file uploads)
```

### Optional Headers
```http
Accept: application/json
X-Request-ID: uuid-v4 (for request tracing)
```

## Rate Limiting

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1738368060
```

## Pagination

All list endpoints support pagination with these query parameters:
- `page`: Page number (0-indexed)
- `size`: Number of items per page
- `sort`: Sort field and direction (e.g., "uploadedAt,desc")

Response includes pagination metadata:
```json
{
  "content": [...],
  "page": 0,
  "size": 20,
  "totalElements": 100,
  "totalPages": 5
}
```

## Filtering & Sorting

### Conversation Filtering
```http
GET /api/files/{fileId}/conversations?protocol=HTTPS&minPackets=1000
```

### Timeline Filtering
```http
GET /api/files/{fileId}/timeline?startTime=1738364700000&endTime=1738368000000
```

## 7. Storage Management (Admin)

### Get Storage Statistics
```http
GET /api/admin/storage/stats

Response: 200 OK
{
  "totalFiles": 42,
  "totalSizeBytes": 2147483648,
  "totalSizeFormatted": "2.0 GB",
  "minioHealth": "UP",
  "bucketName": "tracepcap-files",
  "oldestFile": {
    "fileId": "uuid-v4",
    "fileName": "old-capture.pcap",
    "uploadedAt": 1735776000000,
    "ageInDays": 30
  }
}
```

### List MinIO Objects
```http
GET /api/admin/storage/objects
Query Parameters:
- prefix: string (optional)
- maxKeys: number (default: 1000)

Response: 200 OK
[
  {
    "key": "uuid-v4.pcap",
    "size": 1048576,
    "lastModified": 1738368000000,
    "etag": "5d41402abc4b2a76b9719d911017c592",
    "storageClass": "STANDARD"
  }
]
```

### Clean Up Orphaned Files
```http
POST /api/admin/storage/cleanup

Response: 200 OK
{
  "filesDeleted": 5,
  "spaceSaved": 52428800,
  "deletedFiles": [
    {
      "fileId": "orphan-uuid-1",
      "reason": "No database entry",
      "size": 10485760
    }
  ]
}

Note: Deletes MinIO objects that have no corresponding database entry.
```

### Get Pre-signed Upload URL
```http
POST /api/files/presigned-upload
Content-Type: application/json

Request Body:
{
  "fileName": "capture.pcap",
  "fileSize": 1048576
}

Response: 200 OK
{
  "fileId": "uuid-v4",
  "uploadUrl": "http://localhost:9000/tracepcap-files/uuid-v4.pcap?X-Amz-...",
  "expiresAt": 1738368300000,
  "expiresInSeconds": 300
}

Note: Client uploads directly to MinIO using the pre-signed URL, then calls POST /api/files/{fileId}/confirm
```

### Confirm Direct Upload
```http
POST /api/files/{fileId}/confirm
Content-Type: application/json

Request Body:
{
  "etag": "5d41402abc4b2a76b9719d911017c592"
}

Response: 200 OK
{
  "fileId": "uuid-v4",
  "status": "processing",
  "message": "File upload confirmed, analysis started"
}

Note: Confirms that client successfully uploaded to MinIO, triggers analysis.
```

## WebSocket Support (Future)

### Real-time Progress Updates
```
ws://localhost:8080/ws/files/{fileId}/progress

Message Format:
{
  "type": "progress",
  "fileId": "uuid-v4",
  "progress": 45,
  "currentStep": "Analyzing conversations"
}
```

## Notes

### General
1. All timestamps are in milliseconds (Unix epoch time)
2. All endpoints require the `/api` prefix
3. File size limit: 100MB (configurable via `minio.max-file-size`)
4. Supported file types: `.pcap`, `.pcapng`, `.cap`
5. Default pagination: 20 items per page
6. Maximum page size: 100 items
7. Story generation is asynchronous and may take 30-60 seconds
8. Packet payload is base64-encoded for transport

### MinIO Storage
9. Files are stored in MinIO bucket: `tracepcap-files`
10. File naming convention: `{fileId}.pcap` (UUID + extension)
11. MinIO pre-signed URLs expire after 5 minutes (download) or 5 minutes (upload)
12. Automatic retention: Files older than 90 days are auto-deleted (configurable)
13. MinIO endpoint: `http://localhost:9000` (production should use HTTPS)
14. Bucket versioning: Disabled (to save space)
15. Bucket lifecycle: Enabled (auto-delete old files)

### Database Schema
**Files Table:**
```sql
CREATE TABLE files (
  id UUID PRIMARY KEY,
  file_name VARCHAR(255) NOT NULL,
  file_size BIGINT NOT NULL,
  minio_path VARCHAR(512) NOT NULL,
  uploaded_at TIMESTAMP NOT NULL,
  status VARCHAR(50) NOT NULL,
  packet_count INTEGER,
  total_bytes BIGINT,
  duration BIGINT,
  start_time TIMESTAMP,
  end_time TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Analysis Results Table:**
```sql
CREATE TABLE analysis_results (
  id UUID PRIMARY KEY,
  file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  protocol_distribution JSONB,
  top_conversations JSONB,
  hosts JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Error Handling
16. MinIO connection errors return `503 Service Unavailable`
17. File validation errors return `422 Unprocessable Entity`
18. Duplicate file uploads are prevented by checking MD5 hash
19. If MinIO upload fails, database transaction is rolled back
20. Orphaned files in MinIO are cleaned up by scheduled job (daily at 2 AM)

### Performance Considerations
21. Large files (>50MB) use chunked upload to MinIO
22. File downloads use HTTP range requests for streaming
23. Analysis is performed asynchronously to avoid blocking API
24. Database indexes on `file_id`, `uploaded_at`, `status` for fast queries
25. MinIO uses erasure coding for data redundancy (configurable)
