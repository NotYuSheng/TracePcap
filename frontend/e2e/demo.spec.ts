import { test, expect, Page, Locator } from '@playwright/test';
import {
  NETWORK_NAME,
  DEMO_FILE,
  demoFilePath,
  clearDemoFile,
  seedWeekFiles,
  seedRoleLabels,
  seedNetwork,
} from './demo-fixture';
import { Timeline } from './demo-timeline';

/**
 * Records the README's walkthrough GIF: one capture's life in the current design, then Monitor.
 *
 * Upload a capture with intrusion alerts and the story written in the background; read the
 * Overview; filter the conversations to the flagged ones; look at the network map and open a
 * host; read the story and ask the chat for a Wireshark filter, watching the tools it uses and
 * opening the matching packets; glance at the files and the report drawer; then a monitored
 * network's map, timeline and inventory.
 *
 * Not a smoke test: it asserts only enough to fail loudly rather than record a broken or empty UI.
 * Run via scripts/record-demo.sh, which encodes the GIF and fast-forwards the waits this logs.
 *
 * DEMO_SKIP_UPLOAD=1 opens the already-analysed demo capture instead of uploading it again, for
 * iterating on the script without a fresh analysis and story each time.
 */

/** Pauses, in real milliseconds of finished GIF. BEAT for steps, FEATURE for the payoff. */
const BEAT = Number(process.env.DEMO_BEAT ?? 700);
const FEATURE = Number(process.env.DEMO_FEATURE ?? 1_400);
/** Text read word by word: the story, the chat's answer. */
const READ = FEATURE * 2;
/** Cursor travel before a click. */
const CURSOR = 260;
const SKIP_UPLOAD = process.env.DEMO_SKIP_UPLOAD === '1';

const timeline = new Timeline();

interface SigmaLike {
  getContainer(): HTMLElement;
  getGraph(): { forEachNode(cb: (n: string) => void): void };
  getNodeDisplayData(n: string): { x: number; y: number; size: number } | null;
  framedGraphToViewport(c: { x: number; y: number }): { x: number; y: number };
}

async function beat(page: Page, ms = BEAT) {
  await page.waitForTimeout(ms);
}

/** Smooth scrolling animates every jump; on video that is a slow, byte-heavy pan. Turn it off. */
async function disableSmoothScroll(page: Page) {
  await page.addInitScript(() => {
    const apply = () => {
      const style = document.createElement('style');
      style.textContent = 'html { scroll-behavior: auto !important; }';
      document.head.appendChild(style);
    };
    if (document.head) apply();
    else document.addEventListener('DOMContentLoaded', apply, { once: true });
  });
}

/**
 * Bring a component into view the way an in-page link does: the card (or section) holding
 * `target` scrolls to the top, and the page's scroll-padding-top stops it just below the sticky
 * header. Every component lands at the same height, with its top edge showing.
 */
async function showComponent(target: Locator) {
  await target.evaluate(el => (el.closest('.card, .ov-card, section') ?? el).scrollIntoView({ block: 'start' }));
  await target.page().waitForTimeout(120);
}

/** Move the cursor to an element, then click it: a teleporting pointer reads as a jump cut. */
async function showClick(page: Page, target: Locator) {
  await target.scrollIntoViewIfNeeded({ timeout: 15_000 });
  const box = await target.boundingBox({ timeout: 15_000 });
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 12 });
    await page.waitForTimeout(CURSOR);
  }
  await target.click({ timeout: 15_000 });
}

/** Type at a human pace: an instant fill reads as a glitch. */
async function showType(target: Locator, text: string) {
  await target.click();
  await target.fill('');
  await target.pressSequentially(text, { delay: 22 });
}

/** The analysis rail's sections, by their accessible names. */
async function openSection(page: Page, name: string | RegExp) {
  await page.evaluate(() => window.scrollTo(0, 0));
  const rail = page.locator('nav.analysis-rail');
  const item = typeof name === 'string' ? rail.getByRole('button', { name, exact: true }) : rail.getByRole('button', { name });
  await showClick(page, item.first());
  await page.waitForTimeout(250);
  await page.evaluate(() => window.scrollTo(0, 0));
}

/** Where the biggest nodes are on screen, largest first (Sigma draws to WebGL: no DOM to click). */
async function graphNodePoints(page: Page, count: number) {
  return page.evaluate(n => {
    const s = (window as unknown as { __sigma?: SigmaLike }).__sigma;
    if (!s) return [];
    const rect = s.getContainer().getBoundingClientRect();
    const pts: { x: number; y: number; size: number }[] = [];
    s.getGraph().forEachNode((node: string) => {
      const d = s.getNodeDisplayData(node);
      if (!d) return;
      const v = s.framedGraphToViewport({ x: d.x, y: d.y });
      const x = rect.left + v.x;
      const y = rect.top + v.y;
      if (x > rect.left + 30 && x < rect.right - 30 && y > rect.top + 30 && y < Math.min(rect.bottom, 690) - 20)
        pts.push({ x, y, size: d.size });
    });
    pts.sort((a, b) => b.size - a.size);
    return pts.slice(0, n);
  }, count);
}

async function closeDialogs(page: Page) {
  for (let i = 0; i < 4; i++) {
    if (!(await page.getByRole('dialog').first().isVisible().catch(() => false))) break;
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
  }
}

// Setup is not story: the Monitor half needs eight analysed captures in a network. Minutes of
// progress bars nobody should watch, so they run here with their own timeout.
test.beforeAll(async ({ request }) => {
  test.setTimeout(20 * 60_000);
  if (!SKIP_UPLOAD) await clearDemoFile(request);
  const fileIds = await seedWeekFiles(request);
  await seedNetwork(request, fileIds);
  await seedRoleLabels(request, fileIds.get('week2_personal_laptop_vpn.pcap')!);
});

test('README demo walkthrough', async ({ page, request }) => {
  await disableSmoothScroll(page);
  timeline.start();

  // ── 1. Upload ─────────────────────────────────────────────────────────────────────────────
  // The front door. Intrusion alerts are the opt-in worth showing, and asking for the story now
  // means it is written during the analysis rather than as a wait of its own later.
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Analyse a capture' })).toBeVisible();
  await beat(page, FEATURE);

  let fileId: string;
  if (SKIP_UPLOAD) {
    const list = await (await request.get('/api/v1/files?page=1&pageSize=200')).json();
    fileId = (list.data ?? []).find((f: { fileName: string }) => f.fileName === DEMO_FILE)?.fileId;
    expect(fileId, `${DEMO_FILE} isn't analysed yet; run once without DEMO_SKIP_UPLOAD`).toBeTruthy();
    await page.goto(`/analysis/${fileId}`);
  } else {
    const suricata = page.getByRole('checkbox', { name: /Intrusion alerts/ });
    await showClick(page, suricata);
    await expect(suricata).toBeChecked();
    const story = page.getByRole('checkbox', { name: /Write the story when analysis finishes/ });
    await showClick(page, story);
    await expect(story).toBeChecked();
    await beat(page);
    await page.locator('input[type="file"]').setInputFiles(demoFilePath());
    await beat(page);
    await timeline.fastForward('Upload and analysis (Suricata)', 2, async () => {
      await page.waitForURL(/\/analysis\/[0-9a-f-]{36}/, { timeout: 600_000 });
      await expect(page.getByRole('heading', { name: 'Where the traffic goes' })).toBeVisible({ timeout: 600_000 });
    });
    fileId = page.url().match(/analysis\/([0-9a-f-]{36})/)![1];
  }

  // ── 2. Overview ───────────────────────────────────────────────────────────────────────────
  // The counts and what needs a look, then where the traffic goes and the flows between
  // organisations.
  await expect(page.getByRole('heading', { name: 'Where the traffic goes' })).toBeVisible({ timeout: 60_000 });
  await page.waitForTimeout(1_500);
  await beat(page, FEATURE);
  // A "from …" tag says where a number comes from.
  const source = page.locator('.ov-source').first();
  await showClick(page, source);
  await beat(page, FEATURE);
  await page.keyboard.press('Escape');
  await showComponent(page.getByRole('heading', { name: 'Where the traffic goes' }));
  await beat(page, FEATURE);
  await showComponent(page.getByRole('heading', { name: 'Flows between organisations' }));
  await beat(page, FEATURE);
  await page.evaluate(() => window.scrollTo(0, 0));

  // ── 3. Conversations ──────────────────────────────────────────────────────────────────────
  // The list with its detail pane; the Flagged chip keeps only what nDPI, Suricata or a rule
  // flagged; a click opens one.
  await openSection(page, 'Conversations');
  await expect(page.getByRole('button', { name: 'Flagged', exact: true })).toBeVisible({ timeout: 30_000 });
  await beat(page, FEATURE);
  await showClick(page, page.getByRole('button', { name: 'Flagged', exact: true }));
  await beat(page);
  const rows = page.locator('ul.ccl button.ccl-row');
  if ((await rows.count()) > 1) {
    await showClick(page, rows.nth(1));
  }
  await beat(page, FEATURE);

  // ── 4. Network map ────────────────────────────────────────────────────────────────────────
  // Every host, grouped by the network it is on; play the capture through, then open the
  // busiest host's card.
  await openSection(page, 'Network Visualization');
  await expect(page.getByRole('button', { name: 'Fit view' })).toBeVisible({ timeout: 60_000 });
  await page.waitForTimeout(2_000);
  await showComponent(page.getByRole('heading', { name: 'Traffic' }));
  await beat(page, FEATURE);
  const play = page.getByRole('button', { name: 'Play through the capture' });
  if (await play.isVisible().catch(() => false)) {
    await showClick(page, play);
    await page.waitForTimeout(3_500);
  }
  const nodes = await graphNodePoints(page, 3);
  if (nodes.length) {
    await page.mouse.move(nodes[0].x, nodes[0].y, { steps: 14 });
    await page.waitForTimeout(CURSOR);
    await page.mouse.click(nodes[0].x, nodes[0].y);
    if (await page.getByRole('dialog').first().isVisible({ timeout: 4_000 }).catch(() => false)) {
      await beat(page, FEATURE * 1.5);
      await closeDialogs(page);
    }
  }
  await page.evaluate(() => window.scrollTo(0, 0));

  // ── 5. Story, and the chat with its tools ─────────────────────────────────────────────────
  // The story the LLM wrote in the background; then a question the chat answers by looking
  // things up: each tool shows as it runs, the filter comes back checked, and its packets open.
  await openSection(page, 'Story');
  await timeline.fastForward('Story being written', 2, async () => {
    await expect(page.getByRole('heading', { name: 'The story', exact: true })).toBeVisible({ timeout: 15 * 60_000 });
  });
  await beat(page, READ);
  const ask = page.getByRole('textbox', { name: 'Ask a question about this capture' });
  await showType(ask, process.env.DEMO_QUESTION ?? 'What is the most serious thing here? Give me a Wireshark filter for it.');
  await beat(page);
  await ask.press('Enter');
  // The wait for the first tool fast (a local model thinks for a while first), the first steps at
  // real speed, then the rest of the work fast.
  await timeline.fastForward('The chat thinking', 2, async () => {
    await expect(page.getByText('Looking things up…')).toBeVisible({ timeout: 300_000 });
  });
  await page.waitForTimeout(2_500);
  await timeline.fastForward('The chat looking things up', 2, async () => {
    await expect(page.getByRole('button', { name: /^Used \d+ tools?/ }).last()).toBeVisible({ timeout: 10 * 60_000 });
  });
  // Back to the start of the answer: the panel scrolls to its end when the answer lands.
  await page.evaluate(() => {
    const box = document.querySelector('.story-chat-messages');
    const answers = document.querySelectorAll('.story-chat-messages .chat-msg-ai');
    const last = answers[answers.length - 1] as HTMLElement | undefined;
    if (box && last) box.scrollTop = last.offsetTop - 8;
  });
  await beat(page, READ);
  await showClick(page, page.getByRole('button', { name: /^Used \d+ tools?/ }).last());
  await beat(page, FEATURE);
  const show = page.getByRole('button', { name: 'Show packets' }).first();
  if (await show.isVisible().catch(() => false)) {
    await showClick(page, show);
    await expect(page.getByRole('dialog', { name: 'Matching packets' })).toBeVisible({ timeout: 60_000 });
    await page.waitForTimeout(1_200);
    await beat(page, FEATURE);
    await closeDialogs(page);
  }
  await beat(page);

  // ── 6. Files, and the report ──────────────────────────────────────────────────────────────
  await openSection(page, 'Extracted Files');
  await page.waitForTimeout(1_200);
  await beat(page, FEATURE);
  await openSection(page, 'Capture, rules and report');
  await showClick(page, page.getByRole('button', { name: /Download report/ }));
  await expect(page.getByRole('dialog', { name: 'Download report' })).toBeVisible();
  await beat(page, FEATURE);
  await showClick(page, page.getByText('Full', { exact: true }));
  await beat(page, FEATURE);
  await closeDialogs(page);

  // ── 7. Monitor ────────────────────────────────────────────────────────────────────────────
  // The same analysis over eight weekly captures of one network: what changed, the map at the
  // latest capture, the timeline, and the inventory.
  await showClick(page, page.getByRole('link', { name: 'Monitor' }).first());
  await expect(page.getByRole('heading', { name: 'Monitored networks' })).toBeVisible();
  await beat(page, FEATURE);
  await showClick(page, page.getByRole('link', { name: NETWORK_NAME }).first());
  await expect(page.getByRole('heading', { name: NETWORK_NAME })).toBeVisible({ timeout: 30_000 });
  await page.waitForTimeout(2_000);
  await beat(page, FEATURE);
  await showComponent(page.getByRole('heading', { name: /What changed in the latest capture/ }));
  await page.waitForTimeout(800);
  await beat(page, FEATURE);
  await showComponent(page.getByRole('heading', { name: /Network map/ }));
  await page.waitForTimeout(1_500);
  await beat(page, FEATURE);
  await openSection(page, /^Timeline/);
  await page.waitForTimeout(2_500);
  await beat(page, FEATURE * 1.5);
  await openSection(page, /Devices, addresses and apps|Inventory/);
  // It reads every capture's devices first, which can hold the page before it paints.
  await timeline.fastForward('Inventory loading', 2, async () => {
    await expect(page.getByPlaceholder('Search MAC addresses…')).toBeVisible({ timeout: 120_000 });
    // In the DOM isn't on screen: a page this size can hold the paint while the recorder competes for
    // the CPU, and a take ended on the Timeline with the rail already on Inventory. Wait for two
    // painted frames, which only come once the browser has drawn it.
    await page.evaluate(() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(null)))));
  });
  await page.waitForTimeout(1_000);
  await beat(page, FEATURE * 1.5);
  // The recording's last frames can be lost when the page closes; hold a moment longer.
  await beat(page, FEATURE);

  timeline.write();
});
