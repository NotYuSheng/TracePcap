import { test, expect, Page, Locator } from '@playwright/test';
import {
  NETWORK_NAME,
  DEMO_FILE,
  demoFilePath,
  clearDemoFile,
  seedWeekFiles,
  seedRoleLabels,
  assertNetworkInsights,
  findNetworkId,
  seedNetwork,
} from './demo-fixture';
import { Timeline } from './demo-timeline';

/**
 * Records the README demo: a full pass over the product, analysis first and
 * Monitor second.
 *
 * The arc is one capture's life — upload it, read what the analysis found, ask
 * the LLM to narrate it, filter it, look at its topology and geography — and
 * then the Monitor view, where eight weekly captures of a different network turn
 * the same machinery into change detection over time.
 *
 * Not a smoke test: it asserts only enough to fail loudly rather than record a
 * broken or empty UI. Run via `npm run demo:record`, or scripts/record-demo.sh
 * which also encodes the GIF and fast-forwards the LLM waits this logs.
 */

// Pauses are what the viewer reads as pacing, so they are deliberate, not
// arbitrary waits. They are also the main lever on GIF size — the encoded GIF
// costs ~100KB per second of runtime even on a static page, so keep each hold
// as short as still reads clearly.
//
// PACE divides every hold. The tour visits ten sections, so pauses sized to feel
// natural in isolation add up to a GIF nobody watches to the end; at 3x the
// whole thing still reads, because the viewer is skimming, not studying.
// Override with DEMO_PACE=1 to get the original, slower timing back.
const PACE = Number(process.env.DEMO_PACE ?? 2.5);
const ms = (n: number) => Math.round(n / PACE);

const BEAT = ms(1_000);
const READ = ms(1_800);
/** A glance — used for the "quickly show" steps, which are transitions, not destinations. */
const GLANCE = ms(650);
/** Cursor travel before a click. Short enough to read as intent, not hesitation. */
const CURSOR = ms(300);

const timeline = new Timeline();

/** Hold on the current view so a viewer can take it in before the next step. */
async function beat(page: Page, ms = BEAT) {
  await page.waitForTimeout(ms);
}

/**
 * Bring an element into view, centred. Deliberately not smooth-scrolled: an
 * animated scroll repaints the whole frame for ~1s, and full-frame changes are
 * the worst case for GIF inter-frame compression (a smooth pass costs more
 * bytes than the destination view it lands on). A hard cut costs one frame.
 */
async function reveal(target: Locator) {
  await target.evaluate(el => el.scrollIntoView({ block: 'center' }));
  await target.page().waitForTimeout(120);
}

/**
 * Scroll the window by a screenful. Used where the script says "scroll down to
 * show X" and X is a region rather than one element — reveal() needs a target,
 * this just moves the viewport.
 */
async function scrollBy(page: Page, dy: number) {
  await page.evaluate(y => window.scrollBy(0, y), dy);
  await page.waitForTimeout(150);
}

/**
 * Drive the cursor to an element and click it. Playwright's default click
 * teleports the pointer, which reads as a jump cut on video; a stepped
 * mouse.move makes the interaction legible.
 */
async function showClick(page: Page, target: Locator) {
  // Short timeouts: every call here targets something already asserted visible,
  // so a hang means the element went away. Fail in seconds rather than sitting
  // out the whole test timeout.
  await target.scrollIntoViewIfNeeded({ timeout: 10_000 });
  const box = await target.boundingBox({ timeout: 10_000 });
  if (box) {
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 12 });
    await page.waitForTimeout(CURSOR);
  }
  await target.click({ timeout: 10_000 });
}

/**
 * Dismiss every open modal and wait for them to actually go. Modals stack here,
 * and a lingering backdrop silently swallows the next click on the page
 * underneath.
 */
async function closeAllModals(page: Page) {
  for (let i = 0; i < 4; i++) {
    if (!(await page.getByRole('dialog').first().isVisible().catch(() => false))) break;
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
  }
  await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 5_000 });
}

/** Type at human speed — an instant fill() reads as a glitch on video. */
async function showType(target: Locator, text: string) {
  await target.click();
  await target.fill('');
  await target.pressSequentially(text, { delay: 24 });
}

/**
 * Switch analysis tabs by their visible label, and wait for the route to settle.
 *
 * Scoped to the tab bar: several tab labels are substrings of buttons on the
 * page they open ("Story" vs "Generate Story", "Filter Generator" vs "Generate
 * Filter"), so an unscoped lookup is ambiguous the moment the tab renders.
 */
async function openTab(page: Page, label: RegExp) {
  await showClick(page, page.locator('ul.nav-tabs').getByRole('button', { name: label }).first());
  await page.waitForTimeout(400);
}

/**
 * Jump to a section of the Monitor network-detail page via its sticky side nav.
 *
 * Preferred over scrolling the window: it is how the page is meant to be
 * navigated, it keeps the nav (and its active-link highlight) on camera, and it
 * lands each section consistently regardless of how tall the ones above it grew.
 * The nav scrolls smoothly, so wait for it to settle before filming.
 */
async function gotoSection(page: Page, label: string) {
  const link = page.locator('.tp-section-nav').getByRole('link', { name: label }).first();
  await expect(link, `no "${label}" link in the section nav`).toBeVisible({ timeout: 10_000 });
  await showClick(page, link);
  await page.waitForTimeout(ms(700));
}

// Setup is not story. The Monitor half needs eight analysed captures, a network,
// and generated insights — minutes of progress bars nobody should watch. It runs
// in beforeAll with its own timeout so the recorded test stays short.
let networkId: string;

test.beforeAll(async ({ request }) => {
  test.setTimeout(20 * 60_000);

  // The demo uploads this one on camera, so it must NOT already exist — the
  // backend would dedup it and show the "already uploaded" branch instead.
  await clearDemoFile(request);

  const fileIds = await seedWeekFiles(request);
  networkId = await seedNetwork(request, fileIds);

  // Roles make the drift panels look like an audit in progress rather than a
  // wall of unlabelled IPs.
  await seedRoleLabels(request, fileIds.get('week2_personal_laptop_vpn.pcap')!);

  // Insights are filmed, not generated on camera (step 11) — fail now if absent.
  await assertNetworkInsights(request, networkId);
});

test('README demo walkthrough', async ({ page }) => {
  timeline.start();

  // ── 1. Upload ───────────────────────────────────────────────────────────
  // Open on the upload screen: the product's actual front door, and the only
  // frame that needs no explanation.
  await page.goto('/');
  // Two headings carry this text — the page title and the file-list card.
  await expect(page.getByRole('heading', { name: /Upload PCAP Files/i }).first()).toBeVisible();
  await beat(page, READ);

  // The drop zone's input is visually hidden, so set files on it directly —
  // there is no OS file picker to drive, and none would be recorded anyway.
  await page.locator('input[type="file"]').setInputFiles(demoFilePath());

  // ── 2. Analysis options ────────────────────────────────────────────────
  // nDPI and file extraction default on; Suricata is the deliberate opt-in, so
  // ticking it is the beat worth filming.
  const optionsModal = page.getByRole('dialog');
  await expect(optionsModal.getByText(/Analysis options/i)).toBeVisible({ timeout: 10_000 });
  // One short hold to take in the modal, then act. The two options that are
  // already on need no dwell — only the Suricata tick is a decision.
  await beat(page, BEAT);

  // Checkboxes carry no accessible name (their text lives in sibling divs), so
  // target the Suricata one via the label block that owns it.
  const suricata = optionsModal
    .locator('label.tp-suricata-option input[type="checkbox"]');
  await expect(suricata).not.toBeChecked();
  await showClick(page, suricata);
  await expect(suricata).toBeChecked();
  // Just long enough for the tick to register on camera before moving on.
  await beat(page, GLANCE);

  await showClick(page, optionsModal.getByRole('button', { name: /Start upload/i }));

  // Show the upload/analysis wait briefly, then race through the rest. Suricata
  // makes this the longest wait in the demo (~50s+); the spinner stays on
  // screen, just at 10x.
  await beat(page, BEAT);
  await timeline.fastForward('Upload + analysis (Suricata enabled)', 2, async () => {
    // A single-file upload auto-navigates to the analysis page on success.
    await page.waitForURL(/\/analysis\/[0-9a-f-]{36}/, { timeout: 300_000 });
    await expect(page.getByRole('heading', { name: /Network Traffic Analysis/i })).toBeVisible({
      timeout: 300_000,
    });
    // The page mounts on a loading view while the summary fetches — wait for
    // real content, or the "completed" cut lands on a spinner.
    await expect(page.getByRole('button', { name: /Conversations/i })).toBeVisible({
      timeout: 300_000,
    });
  });
  await beat(page, READ);

  // ── 3. Overview ────────────────────────────────────────────────────────
  // Detected apps and risk flags first, then the protocol/category pie charts —
  // revealed by anchor rather than by a fixed scroll distance, so the charts
  // stay framed even as the panels above them change height.
  await scrollBy(page, 420);
  await beat(page, READ);

  const pieCharts = page.locator('.breakdown-title');
  await expect(pieCharts.first(), 'no breakdown charts on the overview').toBeVisible({
    timeout: 15_000,
  });
  const pieCount = await pieCharts.count();
  for (let i = 0; i < pieCount; i++) {
    // Centre the chart itself, not its heading — recharts renders the pie below
    // the title, and centring the title leaves the pie half off-screen.
    await reveal(pieCharts.nth(i).locator('xpath=..'));
    await beat(page, READ);
  }

  await page.evaluate(() => window.scrollTo(0, 0));
  await beat(page, GLANCE);

  // ── 4. Conversations: filter to Telegram, then inspect one ─────────────
  await openTab(page, /Conversations/i);
  await expect(page.getByRole('heading', { name: /Network Conversations/i })).toBeVisible({
    timeout: 20_000,
  });
  await beat(page, READ);

  // The filter panel is collapsed by default — open it, and hold on the range of
  // filters available before narrowing to one.
  // Scoped to the panel, not the page: "Filter Generator" is also a button here.
  // Not exact-matched either — the toggle wraps its label in two decorative <i>
  // icons, so its accessible name carries whitespace and `exact: true` misses it.
  const filterPanel = page.locator('.conversation-filter-panel');
  await showClick(page, filterPanel.getByRole('button', { name: 'Filters' }).first());
  await beat(page, READ);

  // App badges are buttons, one per detected application. Telegram is the most
  // recognisable app in this capture.
  const telegram = page.getByRole('button', { name: 'Telegram', exact: true }).first();
  await expect(telegram, 'no Telegram badge in the filter panel').toBeVisible({ timeout: 15_000 });
  await beat(page);
  await showClick(page, telegram);
  // Wait for the filtered refetch rather than a fixed sleep.
  await expect(page.getByRole('heading', { name: /Network Conversations/i })).toBeVisible();
  await beat(page, READ);

  // First row of the filtered set. Targeted positionally, not by address: the
  // demo capture's default sort order is data, not contract, and hardcoding
  // "91.108.16.1:527" broke the moment the ordering shifted.
  const firstRow = page.locator('tbody tr').first();
  await expect(firstRow).toBeVisible({ timeout: 15_000 });
  await expect(firstRow).toContainText('192.168.1.77');
  await showClick(page, firstRow);

  const convModal = page.getByRole('dialog');
  await expect(convModal).toBeVisible({ timeout: 15_000 });
  await beat(page, READ);

  // Packet list + session reconstruction live below the modal's fold. Scroll to
  // frame that card rather than to the bottom of the modal: the tabs sit at the
  // card's top, so bottoming out puts the thing being demonstrated off-screen.
  const convBody = convModal.locator('.modal-body');
  const packetTabs = convModal.locator('ul.card-header-tabs');
  await expect(packetTabs, 'packet/session tabs not found').toBeVisible({ timeout: 10_000 });
  await packetTabs.evaluate(el => el.scrollIntoView({ block: 'start' }));
  // Nudge back up so the tab strip isn't flush against the modal's top edge.
  await convBody.evaluate(el => el.scrollBy(0, -70));
  await beat(page, READ);

  // Both views of the same flow: the packet-by-packet table, then the
  // reassembled session.
  for (const tab of [/^Packets/, /^Session/]) {
    await showClick(page, packetTabs.getByRole('button', { name: tab }).first());
    // Session reconstruction is fetched on demand, so the tab opens on a
    // "Reconstructing session…" spinner. Hold until the real content is there —
    // otherwise the demo films the spinner and moves on before it resolves.
    await expect(convModal.getByText(/Reconstructing session/i)).toBeHidden({
      timeout: 60_000,
    });
    await beat(page, READ);
  }

  await convBody.evaluate(el => el.scrollTo(0, 0));
  await beat(page, GLANCE);

  // The remote endpoint is a clickable host chip — it opens that host's identity
  // panel without leaving the conversation.
  const serverChip = convModal.getByText(/^91\.108\./).first();
  await expect(serverChip, 'server endpoint chip not found').toBeVisible({ timeout: 10_000 });
  await showClick(page, serverChip);
  await beat(page, READ);

  // Evidence weighed — the three measured axes behind the identity verdict.
  const hostModal = page.getByRole('dialog').last();
  const evidence = hostModal.getByText('Evidence weighed').first();
  await expect(evidence, 'Evidence weighed section not rendered').toBeVisible({ timeout: 15_000 });
  await reveal(evidence);
  await beat(page, READ);

  // Each axis row expands in place. Hardware is the physical fingerprint (OUI,
  // TTL) — the most legible one to open on camera.
  const hardware = hostModal.locator('[title^="Inspect Hardware"]').first();
  await expect(hardware).toBeVisible({ timeout: 10_000 });
  await showClick(page, hardware);
  await beat(page, READ + 400);

  await closeAllModals(page);

  // ── 5. Story ───────────────────────────────────────────────────────────
  await openTab(page, /Story/i);
  // Not end-anchored: these buttons wrap their label in decorative <i> icons,
  // which pad the computed accessible name — /^Generate Story$/ never matches.
  const generateStory = page.getByRole('button', { name: /Generate Story/i }).first();
  await expect(generateStory, 'Generate Story button not found').toBeVisible({ timeout: 15_000 });
  // No hold before this click: the tab has nothing to read yet — it is an empty
  // "No Story Generated Yet" prompt — so pausing here reads as hesitation.
  // showClick's own cursor travel is the only beat it needs.
  await showClick(page, generateStory);

  // Show the loading state, then race the LLM.
  //
  // Wait for the finished story to render, not for the spinner to disappear:
  // the loading view unmounts a beat before the story paints, and cutting on the
  // spinner filmed the demo tabbing away from a blank Story page while the LLM
  // was still working. "Network Traffic Story" is the heading of the rendered
  // story, so it only exists once there is one.
  await beat(page, BEAT);
  await timeline.fastForward('Generate Story (LLM)', 2, async () => {
    await expect(page.getByRole('heading', { name: /Network Traffic Story/i })).toBeVisible({
      timeout: 300_000,
    });
  });

  // Fail loudly if the LLM errored — a recording that films an error banner and
  // calls it a story is worse than no recording.
  const storyError = page.getByText(/Failed to Generate Story/i);
  await expect(storyError, 'story generation failed — check the LLM server').toBeHidden();
  await beat(page, READ);
  await scrollBy(page, 420);
  await beat(page, READ);
  await page.evaluate(() => window.scrollTo(0, 0));

  // ── 6. Filter generator ────────────────────────────────────────────────
  await openTab(page, /Filter Generator/i);
  const prompt = page.getByPlaceholder(/Show me all HTTP traffic/i);
  await expect(prompt, 'filter prompt box not found').toBeVisible({ timeout: 15_000 });
  await showType(prompt, 'Find any traffic to database, cache, or file-sharing ports');
  await beat(page);

  await showClick(page, page.getByRole('button', { name: /Generate Filter/i }));
  await timeline.fastForward('Generate Filter (LLM)', 2, async () => {
    await expect(page.getByRole('button', { name: /Execute Filter/i })).toBeVisible({
      timeout: 300_000,
    });
  });
  await beat(page, READ);

  await showClick(page, page.getByRole('button', { name: /Execute Filter/i }));
  await timeline.fastForward('Execute Filter', 2, async () => {
    await expect(page.getByRole('button', { name: /Execute Filter/i })).toBeEnabled({
      timeout: 120_000,
    });
  });

  // The page smooth-scrolls itself to the results, landing the "Matching
  // Packets" heading at y≈32 — underneath the ~100px sticky navbar, so the
  // recording showed anonymous packet rows with no heading and no match count.
  //
  // The fix is a small scroll *up*, not a re-scroll: scrollIntoView({block:
  // 'center'}) pushes the heading to mid-viewport and the table's own height
  // then carries the rows off-screen. Wait for the page's animation to settle
  // first, or the nudge is applied mid-flight and undone.
  const matching = page.getByRole('heading', { name: /Matching Packets/i }).first();
  await expect(matching, 'filter returned no results to show').toBeVisible({ timeout: 30_000 });
  await page.waitForTimeout(ms(1_200));
  await scrollBy(page, -90);
  await beat(page, READ + ms(600));

  // Then the matched packets themselves.
  await scrollBy(page, 300);
  await beat(page, READ);

  // ── 7. Extracted files ─────────────────────────────────────────────────
  await openTab(page, /Extracted Files/i);
  await beat(page, READ);
  await scrollBy(page, 450);
  await beat(page, GLANCE);
  await scrollBy(page, 400);
  await beat(page, GLANCE);
  await page.evaluate(() => window.scrollTo(0, 0));
  await beat(page, GLANCE);

  // ── 8. Network visualization ───────────────────────────────────────────
  await openTab(page, /Network Visualization/i);
  const topology = page.getByText('Topology Diagram').first();
  await expect(topology, 'topology diagram not rendered').toBeVisible({ timeout: 30_000 });

  // Frame the graph before doing anything to it. Centring the card *header*
  // (what reveal(topology) does) leaves the plot itself below the fold, so the
  // colour-mode cycle below would recolour edges nobody can see. Centre the
  // graph body instead, wait for the force layout to settle, then fit the view
  // so the whole topology is inside the frame.
  const graphBody = page.locator('.network-diagram-graph-body').first();
  await expect(graphBody).toBeVisible({ timeout: 30_000 });
  await reveal(graphBody);
  await expect(page.getByText(/Computing layout/i)).toBeHidden({ timeout: 120_000 });
  await beat(page, BEAT);
  await showClick(page, page.locator('[title="Fit view"]').first());
  await beat(page, READ);

  // Colour is a single channel, so the three modes are alternatives. Cycling
  // them shows what the same topology says about transport, app, and volume.
  const colorBy = page.locator('select').filter({ hasText: /Transport/ }).first();
  await expect(colorBy).toBeVisible({ timeout: 10_000 });
  for (const mode of ['application', 'volume', 'transport']) {
    await colorBy.selectOption(mode);
    await beat(page, GLANCE + 250);
  }

  // Node label customization — open, show the preview, close.
  await showClick(page, page.locator('[title="Customize node labels"]').first());
  const labelModal = page.getByRole('dialog');
  await expect(labelModal).toBeVisible({ timeout: 10_000 });
  await beat(page, BEAT);
  await labelModal.locator('.modal-body').evaluate(el => el.scrollBy(0, 600));
  await beat(page, READ);
  await closeAllModals(page);

  // Drift the cursor across the graph so node tooltips surface on camera.
  //
  // The graph is drawn to <canvas>, not DOM nodes — there is no per-host element
  // to target, and hovering a named IP is not expressible as a selector. So this
  // sweeps a few points across the plot area instead: with the force layout
  // settled, the dense middle is where the hosts are. Purely visual, so nothing
  // is asserted — a miss costs a dwell frame, not a failed recording.
  const canvas = page.locator('.network-diagram-graph-body canvas').first();
  const plot = await canvas.boundingBox().catch(() => null);
  if (plot) {
    for (const [fx, fy] of [
      [0.5, 0.5],
      [0.38, 0.42],
      [0.62, 0.58],
    ]) {
      await page.mouse.move(plot.x + plot.width * fx, plot.y + plot.height * fy, { steps: 20 });
      await page.waitForTimeout(GLANCE);
    }
  }

  // Hierarchical layout, then fit the view — a hierarchical graph is taller than
  // the viewport, and an unfitted one films as a wall of edges.
  await showClick(page, page.locator('[title="Hierarchical layout"]').first());
  await timeline.fastForward('Hierarchical layout (ELK)', 2, async () => {
    await expect(page.getByText(/Computing layout/i)).toBeHidden({ timeout: 120_000 });
  });
  await showClick(page, page.locator('[title="Fit view"]').first());
  await beat(page, READ + 400);

  // Node-to-node volume: what the topology can't show — how much.
  // Scoped to the card that owns them, so "Show" and "Fullscreen" can't resolve
  // to the topology diagram's controls above.
  const heatmapCard = page
    .locator('.card')
    .filter({ hasText: 'Node-to-Node Volume' })
    .last();
  await reveal(heatmapCard);
  await showClick(page, heatmapCard.getByRole('button', { name: /Show/ }).first());
  await beat(page, BEAT);
  // Fullscreen so the whole matrix is on screen rather than clipped by the card.
  await showClick(page, heatmapCard.locator('[title="Fullscreen"]').first());
  await beat(page, READ + 600);
  await page.keyboard.press('Escape');
  await beat(page, GLANCE);

  // ── 9. Network intelligence ────────────────────────────────────────────
  await openTab(page, /Network Intelligence/i);

  // Frame the default ASN cluster diagram before touching the controls — it is
  // the view the tab actually opens on, and switching to Country immediately
  // means it never appears in the recording.
  const clusterBody = page.locator('.intel-cluster-card-body').first();
  await expect(clusterBody, 'cluster graph not rendered').toBeVisible({ timeout: 30_000 });
  await reveal(clusterBody);
  await beat(page, READ + ms(600));

  // Then regroup by country, which swaps the cluster graph for the world map.
  const groupBy = page.locator('select').filter({ hasText: /ASN \/ Organization/ }).first();
  await expect(groupBy, 'group-by control not found').toBeVisible({ timeout: 20_000 });
  await showClick(page, groupBy);
  await groupBy.selectOption('country');
  await beat(page, READ);

  // Italy is a single-host cluster in this capture — small enough that drilling
  // into it lands on one city (Pistoia) rather than a crowded list.
  //
  // Finding it is awkward: the map is SVG, but the country shapes carry no name
  // or country-code attribute, and the "Italy" caption is a <text> marker with
  // pointer-events:none — so neither is directly targetable. Zooming first and
  // clicking by coordinate doesn't work either: zoom re-centres on the map's
  // middle and pushes Italy out of frame. Instead, match the geography whose
  // bounding box contains the caption, at default zoom, and click that.
  const italyIndex = await page.evaluate(() => {
    const label = [...document.querySelectorAll('text')].find(
      t => t.textContent?.trim() === 'Italy'
    );
    if (!label) return -1;
    const lb = label.getBoundingClientRect();
    const cx = lb.x + lb.width / 2;
    const cy = lb.y + lb.height / 2;
    // Width guard: the caption also sits inside the ocean/background path, which
    // spans the whole map. A country is small by comparison.
    return [...document.querySelectorAll('.rsm-geography')].findIndex(g => {
      const r = g.getBoundingClientRect();
      return (
        cx >= r.x && cx <= r.x + r.width && cy >= r.y && cy <= r.y + r.height && r.width < 200
      );
    });
  });

  if (italyIndex >= 0) {
    const italy = page.locator('.rsm-geography').nth(italyIndex);
    await italy.hover();
    await beat(page, GLANCE);
    await italy.click();
    await beat(page, READ);

    // Drilled in: city markers replace the country view. Click the marker's
    // circle, not its caption — the caption is an unclickable <text> sitting
    // above the country path, which swallows the click ("subtree intercepts
    // pointer events"). Both live in the same marker <g>, so go up and back down.
    const pistoiaMarker = page
      .locator('g')
      .filter({ has: page.locator('text', { hasText: /Pistoia/i }) })
      .last()
      .locator('circle')
      .first();
    if (await pistoiaMarker.isVisible().catch(() => false)) {
      await pistoiaMarker.hover();
      await beat(page, GLANCE);
      await pistoiaMarker.click({ force: true });
      await beat(page, READ);

      // The city detail is an inline side panel, not a dialog — closeAllModals
      // would be a silent no-op here, so dismiss it via its own close button.
      const closePanel = page.getByRole('button', { name: /close/i }).last();
      if (await closePanel.isVisible().catch(() => false)) {
        await showClick(page, closePanel);
      }
    }
  }

  // Top hosts closes the analysis half.
  const topHosts = page.getByText(/Top Hosts/i).first();
  if (await topHosts.isVisible().catch(() => false)) {
    await reveal(topHosts);
  } else {
    await scrollBy(page, 600);
  }
  await beat(page, READ);

  // ── 10. Monitor ────────────────────────────────────────────────────────
  // Same machinery, applied over time instead of within one capture.
  await page.goto('/monitor');
  await expect(page.getByRole('heading', { name: /Network Monitor/i }).first()).toBeVisible({
    timeout: 20_000,
  });
  await beat(page, READ);

  const card = page.getByText(NETWORK_NAME, { exact: true }).first();
  await expect(card, 'demo network card not found').toBeVisible({ timeout: 15_000 });
  await showClick(page, card);
  await page.waitForURL(/\/monitor\/[0-9a-f-]{36}/, { timeout: 30_000 });
  await beat(page, READ);

  // ── 11. The eight-week story ───────────────────────────────────────────
  const captureTimeline = page.locator('#sec-timeline');
  await expect(captureTimeline).toBeVisible({ timeout: 20_000 });
  await reveal(captureTimeline);
  await beat(page, READ);

  // Week 8 is the resolution — violations back near baseline after the audit
  // notice. Its snapshot modal is where per-week detail lives.
  const week8 = captureTimeline.getByText(/week8/i).first();
  await expect(week8, 'week 8 snapshot not found on the timeline').toBeVisible({ timeout: 15_000 });
  await showClick(page, week8);
  const snapModal = page.getByRole('dialog');
  await expect(snapModal).toBeVisible({ timeout: 15_000 });
  await beat(page, READ);

  // Tab through the snapshot's facets. Anchored at the start only, not exact:
  // several tabs append a count badge to their label ("Changes28", "Security6"),
  // so an end-anchored or exact match never fires. Insights is held longest —
  // it lazy-loads on first open.
  for (const tab of [/^Changes/i, /^Security/i, /^Context/i, /^Subnets/i, /^Insights/i]) {
    const t = snapModal.getByRole('button', { name: tab }).first();
    if (!(await t.isVisible().catch(() => false))) continue;
    await showClick(page, t);
    await beat(page, tab.source.includes('Insights') ? READ : GLANCE + 250);
  }
  await closeAllModals(page);

  // The network detail page is long, and it ships a sticky section nav for
  // exactly that reason — so drive it the way an operator would, by clicking
  // through the nav, rather than scrolling the page from the outside. It also
  // puts the nav itself on camera, with the active link tracking the section.
  await gotoSection(page, 'Traffic Overview');
  await beat(page, READ);

  // Change events — the drift the auditor never had to go looking for.
  await gotoSection(page, 'Change Events');
  await beat(page, READ);

  // Devices, then the IP drift panel. 192.0.2.99 is the shadow host: it appears
  // mid-series and never resolves to a labelled device.
  await gotoSection(page, 'Drift Panels');
  await beat(page, READ);

  const shadowIp = page.getByText('192.0.2.99', { exact: true }).first();
  if (await shadowIp.isVisible().catch(() => false)) {
    await showClick(page, shadowIp);
    await expect(page.getByRole('dialog')).toBeVisible({ timeout: 10_000 });
    await beat(page, READ);
    await closeAllModals(page);
  }

  // The remaining panels are a stop-by, not destinations.
  for (const label of [
    'Baseline Definitions',
    'Subnet Definitions',
    'External Events',
    'Analyst Annotations',
  ]) {
    await gotoSection(page, label);
    await beat(page, GLANCE + ms(200));
  }

  // Insights close the demo: the LLM correlating the week-7 drop-off with the
  // audit notice. Generated in setup, filmed here.
  await gotoSection(page, 'Network Insights');
  await beat(page, READ);
  // Then all the way down — the insight narrative runs past the fold, and the
  // last section is the note the whole eight-week story has been building to.
  await page.evaluate(() => window.scrollTo({ top: document.body.scrollHeight }));
  await beat(page, READ + ms(600));

  timeline.write();
});
