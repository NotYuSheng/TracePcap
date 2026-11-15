import { test, expect, Page, Locator, APIRequestContext } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Timeline } from './demo-timeline';

/**
 * The README's short hero GIF: the network diagram, which is the most striking thing TracePcap
 * shows. ~20 seconds on one capture, no LLM: the map full screen and the capture played through,
 * then a zoom onto one address that two devices held in turn, one of them opened, and the map
 * filtered down to the flagged flow (a telnet login to a camera). The capture is
 * `office_showcase.pcap` (`python3 sample-files/gen_small_office.py --showcase`), the small office
 * plus the things the map is best at showing. Recorded with
 * `DEMO_SPEC=hero scripts/record-demo.sh sample-files/TracePcap-Hero.gif`.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const CAPTURE = 'office_showcase.pcap';
const CAPTURE_PATH = path.resolve(here, '../../sample-files', CAPTURE);

const timeline = new Timeline();

/** The capture, uploaded once (kept, not expired) and reused by name after that. */
async function ensureCapture(request: APIRequestContext): Promise<string> {
  const list = await request.get('/api/v1/files?page=1&pageSize=200');
  const existing = ((await list.json()).data ?? []).find(
    (f: { fileName: string; status: string }) => f.fileName === CAPTURE && f.status === 'completed'
  );
  if (existing) return existing.fileId;
  const up = await request.post('/api/v1/files', {
    multipart: {
      file: { name: CAPTURE, mimeType: 'application/octet-stream', buffer: fs.readFileSync(CAPTURE_PATH) },
      enableNdpi: 'true',
      enableSuricata: 'false',
      enableFileExtraction: 'true',
      expires: 'false',
    },
    timeout: 120_000,
  });
  expect(up.ok() || up.status() === 409, `upload failed: ${up.status()}`).toBeTruthy();
  const body = await up.json();
  const fileId: string = body.fileId ?? body.existingFileId;
  await expect
    .poll(async () => (await (await request.get(`/api/v1/files/${fileId}`)).json()).status, { timeout: 180_000 })
    .toBe('completed');
  return fileId;
}

/**
 * A visible pointer: headless video doesn't draw the mouse, so clicks would happen with nothing on
 * screen moving to them.
 */
async function showPointer(page: Page) {
  await page.addInitScript(() => {
    window.addEventListener('DOMContentLoaded', () => {
      const dot = document.createElement('div');
      dot.style.cssText =
        'position:fixed;left:-40px;top:-40px;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:50%;' +
        'background:rgba(89,37,220,.25);border:2px solid #5925dc;pointer-events:none;z-index:2147483647;' +
        'transition:transform .12s ease-out';
      document.body.appendChild(dot);
      document.addEventListener('mousemove', e => {
        dot.style.left = `${e.clientX}px`;
        dot.style.top = `${e.clientY}px`;
      }, true);
      document.addEventListener('mousedown', () => (dot.style.transform = 'scale(.7)'), true);
      document.addEventListener('mouseup', () => (dot.style.transform = ''), true);
    });
  });
}

/** Move to the element in steps (a teleport reads as a jump cut), then click. */
async function showClick(page: Page, target: Locator) {
  const box = await target.boundingBox({ timeout: 10_000 });
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 14 });
    await page.waitForTimeout(220);
  }
  await target.click({ timeout: 10_000 });
}

/** Where a node is on screen, by its label (the last one, when two share it). */
async function nodeOnScreen(page: Page, label: string) {
  return page.evaluate(l => {
    type S = {
      getContainer(): HTMLElement;
      getGraph(): { forEachNode(cb: (n: string, a: { label?: string }) => void): void };
      getNodeDisplayData(n: string): { x: number; y: number } | null;
      framedGraphToViewport(c: { x: number; y: number }): { x: number; y: number };
    };
    const s = (window as unknown as { __sigma?: S }).__sigma;
    if (!s) return null;
    const rect = s.getContainer().getBoundingClientRect();
    let at: { x: number; y: number } | null = null;
    s.getGraph().forEachNode((n, a) => {
      if (a.label !== l) return;
      const d = s.getNodeDisplayData(n);
      if (!d) return;
      const v = s.framedGraphToViewport({ x: d.x, y: d.y });
      at = { x: rect.left + v.x, y: rect.top + v.y };
    });
    return at;
  }, label);
}

test('README hero: the network diagram', async ({ page, request }) => {
  const fileId = await ensureCapture(request);
  await showPointer(page);

  timeline.start();
  await page.goto(`/analysis/${fileId}/network-diagram`);
  // The load, and going full screen, are fast-forwarded: the GIF opens on the map.
  const card = page.locator('.card', { hasText: 'Topology Diagram' }).first();
  await timeline.fastForward('Loading the map', 1, async () => {
    await expect(page.locator('canvas.sigma-nodes')).toBeVisible({ timeout: 60_000 });
    await page.waitForTimeout(1200);
    await card.getByRole('button', { name: 'Fullscreen' }).click();
    await page.waitForTimeout(1500);
  });
  await page.waitForTimeout(1200);

  // Play the capture through: the window sweeps the activity bar, traffic flows on the edges.
  await showClick(page, page.getByRole('button', { name: 'Play through the capture' }));
  await page.waitForTimeout(5000);
  await showClick(page, page.getByRole('button', { name: 'Pause' }));
  await showClick(page, page.getByRole('button', { name: 'Show the whole capture' }));
  await page.waitForTimeout(900);

  // Zoom onto the guest network: one address, 10.20.20.51, held by two devices in turn.
  const phone = await nodeOnScreen(page, 'Visitors-iPhone');
  const other = await nodeOnScreen(page, 'Galaxy-A55');
  expect(phone && other, 'the two devices on 10.20.20.51 are not on the map').toBeTruthy();
  const mid = { x: (phone!.x + other!.x) / 2, y: (phone!.y + other!.y) / 2 - 60 };
  await page.mouse.move(mid.x, mid.y, { steps: 14 });
  for (let i = 0; i < 2; i++) {
    await page.mouse.wheel(0, -120);
    await page.waitForTimeout(160);
  }
  await page.waitForTimeout(2200);

  // Open the visitor's phone: the second device on that address.
  const target = await nodeOnScreen(page, 'Visitors-iPhone');
  await page.mouse.move(target!.x, target!.y, { steps: 16 });
  await page.waitForTimeout(500);
  await page.mouse.click(target!.x, target!.y);
  await expect(page.getByRole('dialog').last()).toBeVisible({ timeout: 10_000 });
  await page.waitForTimeout(2800);
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);

  // Only the flagged traffic: the phone's telnet login to the entrance camera, framed.
  await showClick(page, page.locator('.ng-ctrl-btn', { has: page.locator('.bi-funnel') }));
  const unsafe = page.getByRole('button', { name: /^unsafe protocol/i });
  await expect(unsafe).toBeVisible({ timeout: 10_000 });
  await showClick(page, unsafe);
  await page.waitForTimeout(700);
  await page.keyboard.press('Escape');
  await page.waitForTimeout(600);
  await showClick(page, page.getByRole('button', { name: 'Fit view' }));
  await page.waitForTimeout(3000);
  // Off the map, so the last frame isn't one hovered device with the rest faded.
  await page.mouse.move(1240, 60, { steps: 10 });
  await page.waitForTimeout(1200);

  timeline.write();
});
