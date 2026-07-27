import { APIRequestContext, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Seeds the Office Audit demo scenario (docs/sample-files.rst) via the API.
 *
 * Everything here is setup the GIF should not show: uploading eight captures and
 * waiting out analysis is minutes of progress bars. The recording picks up from
 * the Monitor session, which is where the story actually is.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const MONITOR_DIR = path.resolve(here, '../../sample-files/monitor_large');
const SAMPLE_DIR = path.resolve(here, '../../sample-files');

/** The capture the analysis half of the demo uploads on camera. */
export const DEMO_FILE = 'demo_all_rules.pcap';

export const NETWORK_NAME = 'Office Audit — Corp HQ';
export const NETWORK_DESCRIPTION =
  'Corporate HQ office network — weekly PCAP captures from the managed switch ' +
  'spanning eight weeks. Segment covers staff workstations, servers, printers, and BYOD WiFi.';

/** The eight weekly captures, in capture order. */
export const WEEK_FILES = [
  'week1_baseline.pcap',
  'week2_personal_laptop_vpn.pcap',
  'week3_telnet_bittorrent.pcap',
  'week4_ftp_exfil_gateway_change.pcap',
  'week5_shadow_device_arp_spoof.pcap',
  'week6_peak_violations.pcap',
  'week7_violations_drop_gateway_back.pcap',
  'week8_near_baseline.pcap',
];

/** Role labels from the walkthrough's Step 5 table. 10.0.4.50 is left unlabelled
 *  on purpose — the demo runs Suggest with AI on it. */
export const ROLE_LABELS: [string, string][] = [
  ['10.0.2.10', 'File Server (SMB)'],
  ['10.0.2.20', 'Mail Server (SMTP/IMAP)'],
  ['10.0.2.30', 'Internal Web Server'],
  ['10.0.3.5', 'Floor Printer A (IPP)'],
  ['10.0.3.6', 'Floor Printer B (IPP)'],
  ['10.0.1.10', 'Alice — Staff Workstation'],
  ['10.0.1.11', 'Bob — Staff Workstation'],
  ['10.0.1.12', 'Carol — Staff Workstation'],
  ['10.0.4.20', "Bob's Personal Laptop"],
];

/** Upload one capture and wait for analysis to finish. Returns its fileId. */
async function uploadWeek(request: APIRequestContext, fileName: string): Promise<string> {
  const upload = await request.post('/api/v1/files', {
    multipart: {
      file: {
        name: fileName,
        mimeType: 'application/octet-stream',
        buffer: fs.readFileSync(path.join(MONITOR_DIR, fileName)),
      },
      enableNdpi: 'true',
      enableFileExtraction: 'false',
      source: 'MONITOR',
    },
    timeout: 120_000,
  });
  // 409 = already uploaded (dedup by hash); reuse it rather than re-analysing.
  expect(
    upload.ok() || upload.status() === 409,
    `upload of ${fileName} failed: ${upload.status()}`
  ).toBeTruthy();
  const body = await upload.json();
  const fileId: string = body.fileId ?? body.existingFileId;
  expect(fileId, `no fileId for ${fileName}`).toBeTruthy();

  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const r = await request.get(`/api/v1/files/${fileId}`);
    if (!r.ok()) throw new Error(`status check failed for ${fileName}: ${r.status()}`);
    const status = (await r.json()).status;
    if (status === 'completed') return fileId;
    if (status === 'failed') throw new Error(`analysis failed for ${fileName}`);
    await new Promise(res => setTimeout(res, 2000));
  }
  throw new Error(`analysis timed out for ${fileName}`);
}

/**
 * Ensure all eight captures are uploaded and analysed. Returns fileId by name,
 * in capture order. First run on an empty stack analyses all eight (minutes);
 * later runs reuse them.
 *
 * Reuses by *name* rather than relying on the backend's hash dedup:
 * gen_monitor_large.py seeds `random` but fills payloads with os.urandom, so
 * regenerating the samples changes their hashes and the 409 never fires.
 * Matching on name keeps repeat recordings from piling up near-identical
 * captures.
 *
 * Uploads are sequential: the backend analyses on upload, and eight concurrent
 * nDPI runs would contend for the same worker pool.
 */
export async function seedWeekFiles(
  request: APIRequestContext
): Promise<Map<string, string>> {
  const existing = new Map<string, string>();
  const list = await request.get('/api/v1/files?page=1&pageSize=200');
  if (list.ok()) {
    for (const f of (await list.json()).data ?? []) {
      if (f.status === 'completed' && !existing.has(f.fileName)) {
        existing.set(f.fileName, f.fileId);
      }
    }
  }

  const ids = new Map<string, string>();
  for (const f of WEEK_FILES) {
    ids.set(f, existing.get(f) ?? (await uploadWeek(request, f)));
  }
  return ids;
}

/**
 * Apply the walkthrough's Step 5 role labels against a snapshot, minus the one
 * the demo types on camera and 10.0.4.50 (deliberately left unlabelled so
 * "Suggest with AI" has to characterise it from traffic alone).
 *
 * Roles are per-snapshot — keyed by fileId — and carried forward onto later
 * snapshots when saved, which is what makes the staleness beat work.
 */
export async function seedRoleLabels(
  request: APIRequestContext,
  fileId: string,
  skip: string[] = []
): Promise<void> {
  for (const [ip, label] of ROLE_LABELS) {
    if (skip.includes(ip)) continue;
    const res = await request.put('/api/v1/node-roles', {
      data: {
        entityType: 'IP',
        entityKey: ip,
        roleLabel: label,
        roleDescription: '',
        confirmedByHuman: true,
        fileId,
      },
    });
    expect(res.ok(), `role upsert failed for ${ip}: ${res.status()}`).toBeTruthy();
  }
}

/**
 * Remove every copy of the demo capture so the recording can upload it on camera.
 *
 * The backend dedups by hash: with the file already present, the upload modal
 * shows the "already uploaded" branch and offers to open the existing analysis
 * rather than running one — not the flow the GIF is meant to show. Deleting
 * first is what makes step 1 reproducible on a stack that has recorded before.
 */
export async function clearDemoFile(request: APIRequestContext): Promise<void> {
  const list = await request.get('/api/v1/files?page=1&pageSize=200');
  if (!list.ok()) return;
  for (const f of (await list.json()).data ?? []) {
    if (f.fileName === DEMO_FILE) {
      await request.delete(`/api/v1/files/${f.fileId}`);
    }
  }
}

/** Absolute path to the demo capture, for setInputFiles(). */
export function demoFilePath(): string {
  return path.join(SAMPLE_DIR, DEMO_FILE);
}

/** The demo network's id, or null when it doesn't exist yet. */
export async function findNetworkId(request: APIRequestContext): Promise<string | null> {
  const list = await request.get('/api/v1/monitor/networks');
  if (!list.ok()) return null;
  const body = await list.json();
  const networks = Array.isArray(body) ? body : (body.data ?? []);
  return networks.find((n: { name: string }) => n.name === NETWORK_NAME)?.id ?? null;
}

/**
 * Ensure the demo network exists with all eight weekly snapshots attached, and
 * return its id. Reuses an existing network rather than recreating it: each
 * snapshot POST recomputes drift against its predecessor, and the operator's
 * generated insights hang off the network row.
 */
export async function seedNetwork(
  request: APIRequestContext,
  fileIds: Map<string, string>
): Promise<string> {
  let id = await findNetworkId(request);
  if (!id) {
    const created = await request.post('/api/v1/monitor/networks', {
      data: { name: NETWORK_NAME, description: NETWORK_DESCRIPTION },
    });
    expect(created.ok(), `network create failed: ${created.status()}`).toBeTruthy();
    id = (await created.json()).id as string;
  }

  // Attach only the weeks that aren't already snapshots, so a re-run against a
  // seeded stack is a no-op instead of eight duplicate rows.
  const existing = await request.get(`/api/v1/monitor/networks/${id}/snapshots`);
  const snaps = existing.ok() ? await existing.json() : [];
  const have = new Set(
    (Array.isArray(snaps) ? snaps : (snaps.data ?? [])).map((s: { fileId: string }) => s.fileId)
  );
  for (const [, fileId] of fileIds) {
    if (have.has(fileId)) continue;
    const res = await request.post(`/api/v1/monitor/networks/${id}/snapshots`, {
      data: { fileId },
    });
    expect(res.ok(), `adding snapshot failed: ${res.status()}`).toBeTruthy();
  }
  return id;
}

/**
 * Assert the Monitor half of the demo has something to show.
 *
 * The walkthrough films network insights (step 11) rather than generating them —
 * a ~20s+ LLM call at the very end of a long recording. This fails loudly, and
 * early, rather than letting the run reach step 11 and film an empty panel.
 */
export async function assertNetworkInsights(
  request: APIRequestContext,
  networkId: string
): Promise<void> {
  const res = await request.get(`/api/v1/monitor/networks/${networkId}/insights/latest`);
  expect(
    res.ok(),
    'network insights have not been generated — generate them before recording'
  ).toBeTruthy();
  expect((await res.json()).status, 'network insights are not COMPLETED').toBe('COMPLETED');
}
