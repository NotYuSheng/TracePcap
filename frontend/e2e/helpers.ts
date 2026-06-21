import { APIRequestContext, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PCAP = path.resolve(here, '../../sample-files/ftp.pcap');

/**
 * Upload a small sample pcap and wait until the backend finishes processing it,
 * returning the fileId. Used so the analysis pages have real data to render.
 */
export async function uploadAndProcessFixture(request: APIRequestContext): Promise<string> {
  const upload = await request.post('/api/v1/files', {
    multipart: {
      file: {
        name: 'ftp.pcap',
        mimeType: 'application/octet-stream',
        buffer: fs.readFileSync(FIXTURE_PCAP),
      },
      enableNdpi: 'true',
      enableFileExtraction: 'true',
      source: 'ANALYSIS',
    },
  });
  // 409 = this pcap was already uploaded (dedup by hash); reuse the existing one.
  expect(
    upload.ok() || upload.status() === 409,
    `upload failed: ${upload.status()}`
  ).toBeTruthy();
  const body = await upload.json();
  const fileId: string = body.fileId ?? body.existingFileId;
  expect(fileId).toBeTruthy();

  // Poll until processing finishes; fail fast if the backend marks it 'failed'
  // instead of waiting out the whole timeout.
  const deadline = Date.now() + 60_000;
  let status = 'pending';
  while (Date.now() < deadline) {
    const r = await request.get(`/api/v1/files/${fileId}`);
    if (!r.ok()) {
      throw new Error(`Failed to get file status: ${r.status()} ${r.statusText()}`);
    }
    const body = await r.json();
    status = body.status;
    if (!status) {
      throw new Error(`Response body missing 'status' field: ${JSON.stringify(body)}`);
    }
    if (status === 'completed' || status === 'failed') break;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  expect(status, `file processing did not complete (status: ${status})`).toBe('completed');

  return fileId;
}

/** The JSON body the backend returns for a 502 when the LLM is unreachable. */
export const LLM_UNREACHABLE_502 = {
  status: 502,
  error: 'Bad Gateway',
  message: 'LLM server is not reachable: Connection refused',
  errorCode: 'LLM_UNREACHABLE',
};
