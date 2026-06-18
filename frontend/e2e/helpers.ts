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
  const upload = await request.post('/api/files', {
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

  await expect
    .poll(
      async () => {
        const r = await request.get(`/api/files/${fileId}`);
        return r.ok() ? (await r.json()).status : 'pending';
      },
      { timeout: 60_000, intervals: [1000, 2000] }
    )
    .toBe('completed');

  return fileId;
}

/** The JSON body the backend returns for a 502 when the LLM is unreachable. */
export const LLM_UNREACHABLE_502 = {
  status: 502,
  error: 'Bad Gateway',
  message: 'LLM server is not reachable: Connection refused',
  errorCode: 'LLM_UNREACHABLE',
};
