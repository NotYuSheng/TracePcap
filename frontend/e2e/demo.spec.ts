import { test, expect, Page, Locator } from '@playwright/test';
import {
  NETWORK_NAME,
  demoFilePath,
  clearDemoFile,
  seedWeekFiles,
  seedRoleLabels,
  assertNetworkInsights,
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
// natural in isolation add up to a GIF nobody watches to the end; at 2.5x the
// whole thing still reads, because the viewer is skimming, not studying.
// Override with DEMO_PACE=1 to get the original, slower timing back.
const PACE = Number(process.env.DEMO_PACE ?? 2.5);
const ms = (n: number) => Math.round(n / PACE);

/**
 * Two pause lengths, in real milliseconds of finished GIF.
 *
 * Note these are NOT divided by PACE. PACE shortens the waits *while recording*,
 * so the recording is already the finished timing — there is no speed-up pass on
 * top. A 600ms wait is 600ms on screen, which turned out to be too quick to take
 * a feature in.
 *
 * BEAT   — transitions and steps within a feature: opening a filter, switching a
 *          tab, moving between panels. Enough to follow, not enough to dwell.
 * FEATURE — landing on the thing the section exists to show. A full second is
 *          about the floor for recognising a chart, a diagram or a table before
 *          it cuts away.
 *
 * Override either with DEMO_BEAT / DEMO_FEATURE (milliseconds, as filmed).
 */
const BEAT = Number(process.env.DEMO_BEAT ?? 600);
const FEATURE = Number(process.env.DEMO_FEATURE ?? 1_100);

/** Default for beat() — most calls are the in-between steps, not the payoff. */
const HOLD = BEAT;

/**
 * Content that has to be read word by word rather than recognised — currently
 * just the LLM's answer in the Story tab.
 */
const READ_HOLD = FEATURE * 2;

/** Cursor travel before a click. Short enough to read as intent, not hesitation. */
const CURSOR = ms(300);

const timeline = new Timeline();

/**
 * The slice of Sigma's API this recording uses, via the window.__sigma seam
 * NetworkGraph installs. Structural, not imported: sigma's own types would pull
 * the graph library into the e2e tsconfig for three method signatures.
 */
interface SigmaLike {
  getContainer(): HTMLElement;
  getGraph(): { forEachNode(cb: (n: string) => void): void };
  getNodeDisplayData(n: string): { x: number; y: number; size: number } | null;
  framedGraphToViewport(c: { x: number; y: number }): { x: number; y: number };
}

/** Hold on the current view so a viewer can take it in before the next step. */
async function beat(page: Page, ms = HOLD) {
  await page.waitForTimeout(ms);
}

/**
 * Bring an element into view, centred, and wait for the scroll to land.
 *
 * The app sets html { scroll-behavior: smooth } globally, so this animates over
 * ~1s whether or not the call asks it to — that costs GIF bytes (a full-frame
 * repaint per frame of the pan) but it cannot be opted out of from here, so the
 * thing that matters is not filming the hold before the scroll has arrived.
 */
async function reveal(target: Locator) {
  await target.evaluate(el => el.scrollIntoView({ block: 'center' }));
  await settleScroll(target.page());
}

/**
 * Wait for a scroll to actually land.
 *
 * html { scroll-behavior: smooth } is set globally, so every scrollIntoView and
 * scrollBy on the window animates over ~1s regardless of the flag passed to it.
 * A fixed wait samples that mid-flight, and the hold then films the page still
 * gliding toward its target.
 *
 * Two consecutive equal samples at 40ms. disableSmoothScroll makes scrolls
 * instant, so this normally returns after one confirmation; it stays a poll
 * rather than a fixed wait because a few scrolls here are driven by the app's
 * own handlers (the section nav, the filter results autoscroll) rather than by
 * this file, and those still animate.
 */
async function settleScroll(page: Page) {
  let previous = -1;
  let stable = 0;
  for (let i = 0; i < 60 && stable < 2; i++) {
    const y = await page.evaluate(() => Math.round(window.scrollY));
    stable = y === previous ? stable + 1 : 0;
    previous = y;
    await page.waitForTimeout(40);
  }
}

/**
 * Turn off the app's smooth scrolling for the recording.
 *
 * html { scroll-behavior: smooth } makes every jump animate for ~1s. That is
 * good product behaviour and bad recording behaviour, twice over: the animation
 * dominates the runtime (measured on the Story tab, ~17s of scrolling against
 * ~8s of deliberate holds), and a pan repaints the whole frame on every frame,
 * which is the worst case for GIF inter-frame compression — a smooth scroll
 * costs more bytes than the view it lands on.
 *
 * With this, a scroll is a hard cut: one changed frame, and settleScroll returns
 * almost immediately.
 *
 * addInitScript, not addStyleTag: the recording does two full page loads (/ and
 * /monitor), and a style tag is dropped on navigation. This re-applies itself on
 * every document, before the app's own CSS has a chance to matter.
 */
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

/** Height of the sticky navbar — content scrolled to y=0 hides underneath it. */
const NAVBAR = 110;

/**
 * Put a card's top edge just below the sticky navbar, so its header reads as the
 * top of the screen and the body gets the rest of the viewport.
 *
 * Distinct from reveal(): centring a card leaves its header mid-screen with dead
 * space above, and for a card taller than the fold it pushes the header off the
 * top entirely. Takes the element whose top edge should land — pass the card,
 * not its header, or the header's own offset inside the card is lost.
 */
async function frameCardTop(target: Locator) {
  const page = target.page();
  await target.evaluate(
    (el, nav) => window.scrollBy(0, el.getBoundingClientRect().top - nav),
    NAVBAR,
  );
  await settleScroll(page);
}

/**
 * The enclosing .card of an element inside it (a header, a heading, a label).
 *
 * Matches the class token exactly. contains(@class,"card") also matches
 * "card-header" and "card-body", so it returned the header — a 57px element
 * whose top is the card's top only by coincidence, and whose height never grows
 * when the card expands. That silently mis-framed the heatmap by ~130px and
 * broke a height check that assumed it had the real card.
 */
function cardOf(target: Locator) {
  return target.locator(
    'xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " card ")][1]',
  );
}

/**
 * Scroll the window by a screenful. Used where the script says "scroll down to
 * show X" and X is a region rather than one element — reveal() needs a target,
 * this just moves the viewport.
 */
async function scrollBy(page: Page, dy: number) {
  await page.evaluate(y => window.scrollBy(0, y), dy);
  await settleScroll(page);
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
  // Let the route swap commit, but do not pad the pause: the caller's HOLD is
  // the pause. settleScroll also lands the new tab's scroll position.
  await settleScroll(page);
}

/**
 * Where the biggest nodes are on screen, in viewport coordinates, largest first.
 *
 * Sigma draws to WebGL, so a node has no DOM element, no addressable pixel and
 * no selector — an earlier version of this recording swept blind fractions of
 * the plot area and mostly hovered empty space. NetworkGraph exposes its Sigma
 * instance on window.__sigma for exactly this: ask where the nodes actually are
 * rather than guessing a coordinate and silently filming a miss.
 *
 * Off-screen nodes are dropped. The hierarchical graph is taller than the
 * viewport, and clicking at a negative y lands on whatever is scrolled up there
 * instead — so scroll the graph into view before calling this.
 */
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
      if (x > 20 && x < 1260 && y > 20 && y < 700) pts.push({ x, y, size: d.size });
    });
    // Biggest node = most connected = the most interesting one to open.
    pts.sort((a, b) => b.size - a.size);
    return pts.slice(0, n);
  }, count);
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
  // The section nav scrolls the page itself; wait for that to land rather than
  // adding a fixed delay on top of the caller's HOLD.
  await settleScroll(page);
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
  await disableSmoothScroll(page);
  timeline.start();

  // ── 1. Upload ───────────────────────────────────────────────────────────
  // Open on the upload screen: the product's actual front door, and the only
  // frame that needs no explanation.
  await page.goto('/');
  // Two headings carry this text — the page title and the file-list card.
  await expect(page.getByRole('heading', { name: /Upload PCAP Files/i }).first()).toBeVisible();
  await beat(page, HOLD);

  // The drop zone's input is visually hidden, so set files on it directly —
  // there is no OS file picker to drive, and none would be recorded anyway.
  await page.locator('input[type="file"]').setInputFiles(demoFilePath());

  // ── 2. Analysis options ────────────────────────────────────────────────
  // nDPI and file extraction default on; Suricata is the deliberate opt-in, so
  // ticking it is the beat worth filming.
  const optionsModal = page.getByRole('dialog');
  await expect(optionsModal.getByText(/Analysis options/i)).toBeVisible({ timeout: 10_000 });
  // The modal is a feature in its own right — what the analysis will actually
  // run — so give it the full landing hold before acting on it.
  await beat(page, FEATURE);

  // Checkboxes carry no accessible name (their text lives in sibling divs), so
  // target the Suricata one via the label block that owns it.
  const suricata = optionsModal
    .locator('label.tp-suricata-option input[type="checkbox"]');
  await expect(suricata).not.toBeChecked();
  await showClick(page, suricata);
  await expect(suricata).toBeChecked();
  // Just long enough for the tick to register on camera before moving on.
  await beat(page, HOLD);

  await showClick(page, optionsModal.getByRole('button', { name: /Start upload/i }));

  // Show the upload/analysis wait briefly, then race through the rest. Suricata
  // makes this the longest wait in the demo (~50s+); the spinner stays on
  // screen, just at 10x.
  await beat(page, HOLD);
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
  await beat(page, HOLD);

  // ── 3. Overview ────────────────────────────────────────────────────────
  // The analysis summary first — file, packet count, duration, the headline
  // counts the rest of the tab elaborates on. Framed at the top rather than
  // scrolled past by a fixed distance.
  const summary = page.locator('.analysis-summary').first();
  await expect(summary, 'analysis summary not found').toBeVisible({ timeout: 15_000 });
  await frameCardTop(summary);
  await beat(page, FEATURE);

  // Then the protocol and category pie charts, each with its own header at the
  // top of the screen. Anchored on the breakdown container, not the <h3> and not
  // the chart: framing the heading alone clips it against the navbar, and
  // centring the chart (what reveal did) pushes the header off the top, so the
  // pies read as unlabelled.
  // Both charts share .protocol-breakdown — the category one reuses the class.
  const breakdowns = page.locator('.protocol-breakdown');
  await expect(breakdowns.first(), 'no breakdown charts on the overview').toBeVisible({
    timeout: 15_000,
  });
  const pieCount = await breakdowns.count();
  for (let i = 0; i < pieCount; i++) {
    await frameCardTop(breakdowns.nth(i));
    await beat(page, FEATURE);
  }

  await page.evaluate(() => window.scrollTo(0, 0));
  await beat(page, HOLD);

  // ── 4. Conversations: filter to Telegram, then inspect one ─────────────
  await openTab(page, /Conversations/i);
  await expect(page.getByRole('heading', { name: /Network Conversations/i })).toBeVisible({
    timeout: 20_000,
  });
  await beat(page, HOLD);

  // The filter panel is collapsed by default — frame it at the top of the
  // screen, open it, and hold on the range of filters available before narrowing
  // to one. Framing first means the expanded panel opens into an empty viewport
  // rather than unfolding off the bottom edge.
  // Scoped to the panel, not the page: "Filter Generator" is also a button here.
  // Not exact-matched either — the toggle wraps its label in two decorative <i>
  // icons, so its accessible name carries whitespace and `exact: true` misses it.
  const filterPanel = page.locator('.conversation-filter-panel').first();
  await expect(filterPanel, 'conversation filter panel not found').toBeVisible({
    timeout: 15_000,
  });
  await frameCardTop(filterPanel);
  await beat(page, FEATURE);
  await showClick(page, filterPanel.getByRole('button', { name: 'Filters' }).first());
  // Re-frame: expanding pushes the panel's own height down, and the badges the
  // next step clicks are in the part that just appeared.
  await frameCardTop(filterPanel);
  await beat(page, FEATURE);

  // App badges are buttons, one per detected application. Telegram is the most
  // recognisable app in this capture.
  const telegram = page.getByRole('button', { name: 'Telegram', exact: true }).first();
  await expect(telegram, 'no Telegram badge in the filter panel').toBeVisible({ timeout: 15_000 });
  await beat(page);
  await showClick(page, telegram);
  // Wait for the filtered refetch rather than a fixed sleep.
  await expect(page.getByRole('heading', { name: /Network Conversations/i })).toBeVisible();
  await beat(page, HOLD);

  // First row of the filtered set. Targeted positionally, not by address: the
  // demo capture's default sort order is data, not contract, and hardcoding
  // "91.108.16.1:527" broke the moment the ordering shifted.
  const firstRow = page.locator('tbody tr').first();
  await expect(firstRow).toBeVisible({ timeout: 15_000 });
  await expect(firstRow).toContainText('192.168.1.77');
  await showClick(page, firstRow);

  const convModal = page.getByRole('dialog');
  await expect(convModal).toBeVisible({ timeout: 15_000 });
  await beat(page, FEATURE);

  // The destination host opens its full detail modal: what the host was judged
  // to be, and the signals behind that judgement.
  //
  // The host card, not the IP text beside it — the address itself is inert. This
  // used to be a device-type badge with title="Click for details"; #575/#578
  // collapsed that popup into the shared EntityDetailModal, so the affordance is
  // now the whole host card, matched on its aria-label.
  const hostCard = convModal.getByRole('button', { name: /^Open full details for / }).last();
  await expect(hostCard, 'destination host card not found').toBeVisible({ timeout: 10_000 });
  await showClick(page, hostCard);

  // The host modal stacks on top of the conversation modal, so scope to the last
  // dialog — getByRole('dialog') alone is a strict-mode violation with two open.
  const hostModal = page.getByRole('dialog').last();
  await expect(hostModal, 'host detail modal did not open').toBeVisible({ timeout: 15_000 });
  await beat(page, FEATURE);

  // "Evidence weighed" is the heart of the panel: the independent measured
  // signals (hardware fingerprint, ports/services, behaviour) that the
  // adjudicator combined into one verdict. Scroll it into view inside the modal
  // body — the modal scrolls, the page behind it does not.
  const evidence = hostModal.getByText(/Evidence weighed/i).first();
  if (await evidence.isVisible().catch(() => false)) {
    await evidence.evaluate(el => el.scrollIntoView({ block: 'center' }));
    await beat(page, FEATURE);

    // Expand the hardware axis — the MAC OUI match that anchors the verdict.
    const hardware = hostModal.getByRole('button', { name: /Hardware/i }).first();
    if (await hardware.isVisible().catch(() => false)) {
      await showClick(page, hardware);
      await beat(page, FEATURE);
    }
  }
  // Back to the conversation modal — the host modal stacked on top of it, so
  // close only that one rather than both.
  //
  // Asserted on the host modal's own id and the dialog count, not on
  // expect(hostModal).toBeHidden(): hostModal is getByRole('dialog').last(),
  // which re-resolves after the close to the conversation modal underneath — so
  // a toBeHidden() on it would be checking the wrong element and fail even
  // though the right thing happened.
  await page.keyboard.press('Escape');
  await expect(page.locator('#entity-detail-title')).toHaveCount(0, { timeout: 10_000 });
  await expect(page.getByRole('dialog')).toHaveCount(1);
  await beat(page, HOLD);


  const convBody = convModal.locator('.modal-body');
  const packetTabs = convModal.locator('ul.card-header-tabs');

  // Packet list + session reconstruction live below the modal's fold. Scroll to
  // frame that card rather than to the bottom of the modal: the tabs sit at the
  // card's top, so bottoming out puts the thing being demonstrated off-screen.
  await expect(packetTabs, 'packet/session tabs not found').toBeVisible({ timeout: 10_000 });
  await packetTabs.evaluate(el => el.scrollIntoView({ block: 'start' }));
  // Nudge back up so the tab strip isn't flush against the modal's top edge.
  await convBody.evaluate(el => el.scrollBy(0, -70));
  await beat(page, FEATURE);

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
    // Re-frame after the content lands: the pre-click framing leaves the tab
    // strip at y≈438 of a 720px viewport, pushing the table off the bottom edge.
    //
    // Position the strip near the modal's top edge, so the table below it gets
    // the rest of the height. Anchoring on the strip rather than scrolling
    // to the bottom matters: the session panel finishes growing *after* the
    // payload first renders, so scrollHeight read at this moment is stale and a
    // scrollTo(scrollHeight) stops ~54px short — which is what kept filming the
    // tab strip at y≈400 with the table hanging off the bottom edge. Scrolling
    // by the strip's own offset overshoots that stale extent, and the browser
    // honours it once the content has grown.
    let settled = 0;
    let lastMax = -1;
    for (let i = 0; i < 40 && settled < 4; i++) {
      const max = await convBody.evaluate(el => el.scrollHeight - el.clientHeight);
      settled = max === lastMax ? settled + 1 : 0;
      lastMax = max;
      await page.waitForTimeout(150);
    }
    await convBody.evaluate(el => {
      const strip = el.querySelector('ul.card-header-tabs');
      if (strip) {
        el.scrollBy(0, strip.getBoundingClientRect().top - el.getBoundingClientRect().top - 40);
      }
    });
    await beat(page, HOLD);
  }

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
  await beat(page, HOLD);
  await timeline.fastForward('Generate Story (LLM)', 2, async () => {
    await expect(page.getByRole('heading', { name: /Network Traffic Story/i })).toBeVisible({
      timeout: 300_000,
    });
  });

  // Fail loudly if the LLM errored — a recording that films an error banner and
  // calls it a story is worse than no recording.
  const storyError = page.getByText(/Failed to Generate Story/i);
  await expect(storyError, 'story generation failed — check the LLM server').toBeHidden();
  // Short: the very next thing is a scroll to the chat card, so a full hold here
  // just delays the section on a view the panel walk returns to anyway.
  await beat(page, HOLD);

  // Ask the LLM first — it is the one genuinely interactive thing on this tab,
  // and it is also first in page order, so leading with it means the section
  // reads top-to-bottom rather than doubling back.
  //
  // A suggested question rather than typed prose: it is one click, it is
  // guaranteed answerable against this story, and it puts the affordance itself
  // on camera.
  const chatCard = page.locator('.card').filter({ hasText: 'Ask the LLM' }).first();
  await expect(chatCard, 'Ask the LLM card not found').toBeVisible({ timeout: 15_000 });
  await frameCardTop(chatCard);
  await beat(page, FEATURE);

  // A suggested question only *fills* the box — it does not send. So click one
  // to show the affordance, hold while the text lands in the input, then send.
  const suggestion = chatCard.getByRole('button').filter({ hasText: /\?/ }).first();
  const chatInput = chatCard.getByPlaceholder(/Ask a question about this story/i);
  await expect(suggestion, 'no suggested question to click').toBeVisible({ timeout: 10_000 });
  await showClick(page, suggestion);
  await beat(page, HOLD);
  await expect(chatInput).not.toHaveValue('');
  await chatInput.press('Enter');

  // Another LLM round-trip, so race it. Wait on the "Thinking..." bubble going
  // away rather than on an answer selector: the assistant bubble carries only
  // layout classes, so there is nothing stable to match on it, and the spinner
  // is unambiguous while it is up.
  await beat(page, HOLD);
  await timeline.fastForward('Story Q&A (LLM)', 2, async () => {
    await expect(chatCard.getByText(/Thinking\.\.\./)).toBeHidden({ timeout: 300_000 });

    // "Thinking..." disappearing means the first token landed, not that the
    // answer is done — the reply streams in, so re-framing on that signal filmed
    // a half-written sentence scrolling away. Hold until the text stops growing
    // (two equal samples). Inside the fast-forward span: this is still waiting
    // on the model, so it should race like the rest of it.
    let previous = -1;
    for (let i = 0; i < 40; i++) {
      const length = (await chatCard.innerText()).length;
      if (length === previous) break;
      previous = length;
      await page.waitForTimeout(500);
    }
  });

  // Then hold on the answer, properly — this is the payoff of the section, and
  // the reply is prose that has to actually be read. Re-frame first: the answer
  // grows the card, so the pre-send position no longer has the reply in shot.
  await frameCardTop(chatCard);
  await beat(page, READ_HOLD);

  // The rest of the Story page is stacked panels, not one blob of prose, and the
  // point of the tab is how they relate: deterministic findings and full-dataset
  // aggregates are computed, the LLM only writes prose over them. A single
  // scrollBy past the lot showed none of it, so stop on each in page order with
  // its header at the top of the screen.
  //
  // Anchored on each panel's own heading rather than by scroll distance — the
  // panels are conditional (aggregates, findings, and investigation each render
  // only when the story has them), so any fixed offset lands somewhere different
  // depending on what this capture produced.
  for (const [label, heading] of [
    // The narrative itself, with its Key Events rail alongside.
    ['narrative', /^Narrative/],
    // What the LLM was given and what it's allowed to do with it.
    ['generation settings', /How stories are generated/i],
    // Pre-computed analytics over the whole capture, not a sample.
    ['traffic intelligence', /Traffic Intelligence/i],
    // The detector output the narrative is required to cover.
    ['deterministic findings', /Deterministic Findings/i],
    // What the LLM went back and looked up while writing.
    ['investigation steps', /Investigation/i],
  ] as const) {
    const panelHeading = page.getByText(heading).first();
    if (!(await panelHeading.isVisible().catch(() => false))) continue;
    // Frame the enclosing card, not the heading: scrolling the heading itself to
    // the top clips the card's own header padding and border, so the panel reads
    // as starting mid-way through.
    const card = cardOf(panelHeading);
    await frameCardTop((await card.count()) ? card.first() : panelHeading);
    // A brief stop, not a reading pause: these panels are dense enough that
    // nobody reads them off a GIF, so the job here is to show that they exist
    // and what shape they are. The Ask-the-LLM answer above is the one thing on
    // this tab that has to be read, and it keeps its long hold.
    await beat(page, FEATURE);
    // Findings is the exception worth an extra look — it is the evidence the
    // narrative is accountable to, and the densest panel on the page.
    if (label === 'deterministic findings') await beat(page, HOLD);
  }

  
  await page.evaluate(() => window.scrollTo(0, 0));

  // ── 6. Filter generator ────────────────────────────────────────────────
  await openTab(page, /Filter Generator/i);
  const prompt = page.getByPlaceholder(/Show me all HTTP traffic/i);
  await expect(prompt, 'filter prompt box not found').toBeVisible({ timeout: 15_000 });
  // Frame "Ask in Natural Language" at the top before typing, so the prompt box,
  // the button and the generated filter below it all stay in one shot — the tab
  // otherwise opens with the card halfway down and the result lands off-screen.
  await frameCardTop(cardOf(prompt));
  await beat(page, FEATURE);
  await showType(prompt, 'Find any traffic to database, cache, or file-sharing ports');
  await beat(page);

  await showClick(page, page.getByRole('button', { name: /Generate Filter/i }));
  await timeline.fastForward('Generate Filter (LLM)', 2, async () => {
    await expect(page.getByRole('button', { name: /Execute Filter/i })).toBeVisible({
      timeout: 300_000,
    });
  });

  // The generated BPF expression is the payload of this section — the whole
  // point is that plain English became a real filter. Frame it and hold before
  // executing, or it flashes past on the way to the results table.
  // #filter, not a <code>/<pre>: the generated expression renders into an
  // *editable* Form.Control so the analyst can tweak it before running. A
  // previous version matched 'code, pre' behind an isVisible() guard, which
  // never matched and silently skipped this whole step.
  const generated = page.locator('#filter');
  await expect(generated, 'no generated filter expression to show').toBeVisible({
    timeout: 20_000,
  });
  await expect(generated, 'generated filter is empty').not.toHaveValue('');
  // Frame the card rather than centring the expression: the explanation above it
  // and the Execute button below are both part of what just happened, and
  // centring the <code> alone crops one or the other.
  await frameCardTop(cardOf(generated));
  await beat(page, FEATURE);

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
  // The page smooth-scrolls itself here regardless of disableSmoothScroll (it is
  // the app's own scrollIntoView), so wait for it to land before nudging.
  await settleScroll(page);
  await scrollBy(page, -90);
  await beat(page, FEATURE);

  // Then the matched packets themselves.
  await scrollBy(page, 300);
  await beat(page, FEATURE);

  // ── 7. Extracted files ─────────────────────────────────────────────────
  await openTab(page, /Extracted Files/i);

  // The Files card is the section — carrier files reassembled out of the packet
  // stream. Frame its header at the top and stop there: no second scroll, since
  // the rows below already fill the shot and carrying on only reached footer
  // whitespace.
  const filesHeading = page.getByRole('heading', { name: /^Files$/ }).first();
  await expect(filesHeading, 'extracted files card not found').toBeVisible({ timeout: 20_000 });
  await frameCardTop(cardOf(filesHeading));
  await beat(page, FEATURE);

  // ── 8. Network visualization ───────────────────────────────────────────
  await openTab(page, /Network Visualization/i);
  const topology = page.getByText('Topology Diagram').first();
  await expect(topology, 'topology diagram not rendered').toBeVisible({ timeout: 30_000 });

  // Frame the graph before doing anything to it. Anchor on the card *header*
  // rather than centring the graph body: centring pushes the header off the top
  // and the diagram then reads as a floating canvas with no title. Pinning the
  // header just under the sticky navbar keeps "Topology Diagram" on screen with
  // the whole plot below it.
  const graphBody = page.locator('.network-diagram-graph-body').first();
  await expect(graphBody).toBeVisible({ timeout: 30_000 });
  // The card has no class of its own, so reach it structurally — but note it is
  // the graph body's *grandparent*: the body is a .card-body, and the header
  // ("Topology Diagram") is its sibling, so xpath=.. lands inside the card and
  // excludes the very header this is trying to keep on screen.
  //
  // Position it explicitly rather than via scrollIntoView + a nudge: the card
  // sits near the top of the page, so block:'start' is already clamped at scroll
  // 0 and a corrective scrollBy is silently a no-op. The card is ~570px against
  // a 720px viewport, so anchoring its top just under the ~100px sticky navbar
  // fits the header and the whole diagram in one frame.
  const topologyCard = graphBody.locator('xpath=../..');
  const frameTopology = () =>
    topologyCard.evaluate(el => window.scrollBy(0, el.getBoundingClientRect().top - 110));
  await frameTopology();
  await expect(page.getByText(/Computing layout/i)).toBeHidden({ timeout: 120_000 });
  await beat(page, HOLD);
  await showClick(page, page.locator('[title="Fit view"]').first());
  // Re-frame after the layout settles and the camera has fitted: both change the
  // card's height, so the position set before them no longer holds the header
  // under the navbar. Framing only once filmed a headerless canvas.
  await frameTopology();
  await beat(page, FEATURE);

  // Cycle the edge-colour modes. Same topology, recoloured three ways: by
  // transport protocol, by detected application, then by volume — which also
  // swaps in a magnitude legend. Held on each so the recolour is legible rather
  // than a flicker, and re-framed because the volume mode adds a legend row that
  // grows the card and pushes the header back off the top.
  // Anchored on the option values it must contain, not on its rendered text: the
  // "Color edges by" Form.Label has no htmlFor, so getByLabel cannot reach it,
  // and filtering a <select> by hasText matches against its options — which
  // silently matched nothing here and skipped the whole cycle.
  const edgeColorSelect = page
    .locator('select:has(option[value="transport"]):has(option[value="volume"])')
    .first();
  await expect(edgeColorSelect, 'edge-colour select not found').toBeVisible({ timeout: 10_000 });
  for (const mode of ['application', 'volume', 'transport']) {
    await edgeColorSelect.selectOption(mode);
    await frameTopology();
    await beat(page, FEATURE);
  }

  // Node label customization — open, show the preview, close.
  await showClick(page, page.locator('[title="Customize node labels"]').first());
  const labelModal = page.getByRole('dialog');
  await expect(labelModal).toBeVisible({ timeout: 10_000 });
  await beat(page, FEATURE);
  await labelModal.locator('.modal-body').evaluate(el => el.scrollBy(0, 600));
  await beat(page, FEATURE);
  await closeAllModals(page);

  // Drift the cursor over the three biggest hosts so their hover state and
  // labels surface on camera. Purely visual, so nothing is asserted — an empty
  // list costs a few dwell frames, not a failed recording.
  // frameTopology, not reveal(): centring the graph body pushes the card header
  // back above the fold, which is the framing this section is meant to hold.
  await frameTopology();
  await page.waitForTimeout(ms(600));
  for (const pt of await graphNodePoints(page, 3)) {
    await page.mouse.move(pt.x, pt.y, { steps: 20 });
    // A dwell per node, not a section pause — three of these back to back at the
    // full HOLD would read as the demo stalling on an idle graph.
    await page.waitForTimeout(Math.round(HOLD / 2));
  }

  // Hierarchical layout, then fit the view — a hierarchical graph is taller than
  // the viewport, and an unfitted one films as a wall of edges.
  await showClick(page, page.locator('[title="Hierarchical layout"]').first());
  await timeline.fastForward('Hierarchical layout (ELK)', 2, async () => {
    await expect(page.getByText(/Computing layout/i)).toBeHidden({ timeout: 120_000 });
  });
  await showClick(page, page.locator('[title="Fit view"]').first());
  await beat(page, FEATURE);

  // Open one host's details from the graph. The topology is the obvious place a
  // viewer would ask "what is that node?", and the answer — the same identity
  // panel the rest of the app opens — is the point of the whole graph.
  //
  // Read the coordinates *after* the fit-view camera animation has settled. Fit
  // view animates over ~300ms, and positions sampled mid-animation are stale by
  // the time the click lands: the click then hits empty canvas and the modal
  // never opens. This bit the recording once already.
  await page.waitForTimeout(ms(900));
  const [nodePoint] = await graphNodePoints(page, 1);
  expect(nodePoint, 'no graph node found to open — is window.__sigma exposed?').toBeTruthy();

  await page.mouse.move(nodePoint.x, nodePoint.y, { steps: 16 });
  await beat(page, HOLD);
  await page.mouse.click(nodePoint.x, nodePoint.y);

  // Asserted, not best-effort: this step is the reason the section exists, so a
  // miss should fail the recording rather than quietly skip and leave a gap.
  //
  // Anchored on the modal's title id, not on the text "Node Details": #578
  // collapsed that modal into the shared EntityDetailModal, whose title is the
  // host's own display name and therefore varies by node.
  const nodeModal = page.locator('.modal:has(#entity-detail-title)').first();
  await expect(nodeModal, 'clicking a graph node did not open host details').toBeVisible({
    timeout: 15_000,
  });
  await beat(page, FEATURE);
  // Scroll past the header so the identity detail is in shot, not just the title.
  await nodeModal.locator('.modal-body').evaluate(el => el.scrollBy(0, 320));
  await beat(page, FEATURE);
  await closeAllModals(page);

  // Close the section on the node-to-node volume heatmap: the same traffic the
  // topology draws as edges, read as a matrix instead — which pairs actually
  // carry the bytes. Collapsed by default, so it has to be opened.
  const heatmapCard = cardOf(page.getByText('Node-to-Node Volume').first());
  await expect(heatmapCard, 'heatmap card not found').toBeVisible({ timeout: 15_000 });
  await frameCardTop(heatmapCard);
  await showClick(page, heatmapCard.getByRole('button', { name: /^Show/ }).first());
  await expect(page.locator('.tp-heatmap-body'), 'heatmap did not expand').toBeVisible({
    timeout: 20_000,
  });
  // Re-frame once the matrix has finished laying out. The body turning visible is
  // not the end of it — the grid keeps growing for a few hundred ms, so framing
  // on visibility alone used stale geometry and left the card ~130px low, with
  // the topology's tail still occupying the top of the shot.
  await expect
    .poll(() => heatmapCard.evaluate(el => Math.round(el.getBoundingClientRect().height)), {
      timeout: 20_000,
      intervals: [120],
    })
    .toBeGreaterThan(300);
  let lastHeight = -1;
  for (let i = 0; i < 30; i++) {
    const h = await heatmapCard.evaluate(el => Math.round(el.getBoundingClientRect().height));
    if (h === lastHeight) break;
    lastHeight = h;
    await page.waitForTimeout(100);
  }
  await frameCardTop(heatmapCard);
  await beat(page, BEAT);

  // Zoom out until the whole matrix fits the viewport. At the default 19px per
  // cell a 50-host grid is far taller than the fold, so the recording only ever
  // showed its top-left corner. The control steps through fixed sizes and
  // disables itself at MIN_CELL, so drive it by that rather than a fixed count.
  // Measure the grid itself, not the card: the card keeps its full width no
  // matter how small the cells get, so a width test on it never tightens and a
  // height-only test overshoots — the first run zoomed to 6px/cell and left the
  // right half of the panel empty.
  const grid = heatmapCard.locator('svg, canvas').first();
  const zoomOut = heatmapCard.locator('[title="Zoom out"]').first();
  // Budget from the live viewport, not a literal 720: the recording size lives in
  // playwright.config.ts, and hardcoding it here would silently stop fitting if
  // that changed. The reserve covers the navbar plus the card's own header,
  // legend and footnote, which sit outside the grid box being measured.
  const gridBudget = page.viewportSize()!.height - NAVBAR - 150;
  for (let i = 0; i < 8; i++) {
    if (await zoomOut.isDisabled().catch(() => true)) break;
    const box = await grid.boundingBox();
    if (box && box.height <= gridBudget) break;
    await zoomOut.click();
    await page.waitForTimeout(200);
  }
  await frameCardTop(heatmapCard);
  await beat(page, FEATURE);

  // ── 9. Network intelligence ────────────────────────────────────────────
  await openTab(page, /Network Intelligence/i);

  // Frame the default ASN cluster diagram before touching the controls — it is
  // the view the tab actually opens on, and switching to Country immediately
  // means it never appears in the recording.
  const clusterBody = page.locator('.intel-cluster-card-body').first();
  await expect(clusterBody, 'cluster graph not rendered').toBeVisible({ timeout: 30_000 });
  // Frame the card, not the body: "Network Cluster View" lives in the sibling
  // Card.Header, so centring the body alone leaves the diagram unlabelled.
  await frameCardTop(clusterBody.locator('xpath=..'));
  await beat(page, FEATURE);

  // Then regroup by country, which swaps the cluster graph for the world map.
  const groupBy = page.locator('select').filter({ hasText: /ASN \/ Organization/ }).first();
  await expect(groupBy, 'group-by control not found').toBeVisible({ timeout: 20_000 });
  await showClick(page, groupBy);
  await groupBy.selectOption('country');
  await beat(page, FEATURE);

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
    await beat(page, HOLD);
    await italy.click();
    await beat(page, FEATURE);

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
      await beat(page, HOLD);
      await pistoiaMarker.click({ force: true });
      await beat(page, FEATURE);

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
  await beat(page, HOLD);

  // ── 10. Monitor ────────────────────────────────────────────────────────
  // Same machinery, applied over time instead of within one capture.
  await page.goto('/monitor');
  await expect(page.getByRole('heading', { name: /Network Monitor/i }).first()).toBeVisible({
    timeout: 20_000,
  });
  await beat(page, HOLD);

  const card = page.getByText(NETWORK_NAME, { exact: true }).first();
  await expect(card, 'demo network card not found').toBeVisible({ timeout: 15_000 });
  await showClick(page, card);
  await page.waitForURL(/\/monitor\/[0-9a-f-]{36}/, { timeout: 30_000 });
  await beat(page, HOLD);

  // ── 11. The eight-week story ───────────────────────────────────────────
  const captureTimeline = page.locator('#sec-timeline');
  await expect(captureTimeline).toBeVisible({ timeout: 20_000 });
  await reveal(captureTimeline);
  await beat(page, FEATURE);

  // Week 8 is the resolution — violations back near baseline after the audit
  // notice. Its snapshot modal is where per-week detail lives.
  const week8 = captureTimeline.getByText(/week8/i).first();
  await expect(week8, 'week 8 snapshot not found on the timeline').toBeVisible({ timeout: 15_000 });
  await showClick(page, week8);
  const snapModal = page.getByRole('dialog');
  await expect(snapModal).toBeVisible({ timeout: 15_000 });

  // The modal opens on the Network Diagram tab, whose graph is fetched per
  // snapshot. Wait for it properly before holding, in two steps — the spinner
  // clearing is not the same as the graph being drawn:
  //   1. the fetch spinner goes away, then
  //   2. Sigma mounts its WebGL canvases and paints.
  // Waiting only on the spinner left a window where the modal was open over an
  // empty grey panel, which is exactly what the hold then filmed. This is also
  // why the tab loop below skips Diagram — it is already on screen.
  await expect(snapModal.locator('.spinner-border')).toHaveCount(0, { timeout: 120_000 });
  await expect(snapModal.locator('canvas.sigma-nodes')).toBeVisible({ timeout: 120_000 });
  // Sigma paints a frame after mounting; without this the first held frame can
  // still be the blank canvas it mounted with. Waiting on the paint is not a
  // pause — poll for it so this stop lasts one HOLD like every other, instead of
  // HOLD plus a fixed 1.2s.
  await expect
    .poll(
      () =>
        page.evaluate(() => {
          const c = document.querySelector('canvas.sigma-nodes') as HTMLCanvasElement | null;
          return c ? c.width * c.height : 0;
        }),
      { timeout: 30_000, intervals: [100] },
    )
    .toBeGreaterThan(0);
  await beat(page, FEATURE);

  // Tab through the snapshot's facets. Matched loosely and scoped to the pill
  // strip — NOT start-anchored. Every tab label is preceded by a decorative <i>
  // icon, which pads the computed accessible name with whitespace, so /^Changes/
  // matches nothing; the accessible names are actually " Changes28", " Security6",
  // " Context & Notes". Anchoring silently matched zero tabs and the whole loop
  // `continue`d past every one, filming a 2-second flash of the diagram instead
  // of the five panels.
  //
  // Each tab gets a real hold rather than a glance: this modal is the per-week
  // detail the whole eight-week story resolves to, and a viewer who cannot read
  // a panel has no reason to care that it exists. Security and Insights both
  // fetch on first open, so wait for their content, not just for the click.
  const snapTabs = snapModal.locator('ul.nav-pills');
  for (const tab of [/Changes/i, /Security/i, /Context/i, /Subnets/i, /Insights/i]) {
    const t = snapTabs.getByRole('button', { name: tab }).first();
    // Asserted, not skipped: a missing tab is a broken recording, and silently
    // continuing is what hid this bug in the first place.
    await expect(t, `snapshot tab ${tab} not found`).toBeVisible({ timeout: 10_000 });
    await showClick(page, t);
    // Wait on the spinner element, not on loading copy: Insights renders a bare
    // <Spinner> with no text at all, so a text assertion passes instantly while
    // the spinner is still up — which is exactly the bug this is fixing.
    await expect(snapModal.locator('.spinner-border')).toHaveCount(0, { timeout: 120_000 });
    // A tab swap repaints the whole modal body. Wait for the new panel to have
    // laid out (non-zero height) rather than adding a fixed delay: a fixed one
    // made these six stops visibly longer than the rest of the tour.
    await expect
      .poll(() => snapModal.locator('.modal-body').evaluate(el => el.scrollHeight), {
        timeout: 15_000,
        intervals: [100],
      })
      .toBeGreaterThan(0);
    await beat(page, FEATURE);
  }
  await beat(page, HOLD);
  await closeAllModals(page);

  // The network detail page is long, and it ships a sticky section nav for
  // exactly that reason — so drive it the way an operator would, by clicking
  // through the nav, rather than scrolling the page from the outside. It also
  // puts the nav itself on camera, with the active link tracking the section.
  await gotoSection(page, 'Traffic Overview');
  await beat(page, FEATURE);

  // Change events — the drift the auditor never had to go looking for.
  await gotoSection(page, 'Change Events');
  await beat(page, FEATURE);

  // Devices, then the IP drift panel. 192.0.2.99 is the shadow host: it appears
  // mid-series and never resolves to a labelled device.
  await gotoSection(page, 'Drift Panels');
  await beat(page, FEATURE);

  const shadowIp = page.getByText('192.0.2.99', { exact: true }).first();
  if (await shadowIp.isVisible().catch(() => false)) {
    await showClick(page, shadowIp);
    const ipModal = page.getByRole('dialog');
    await expect(ipModal).toBeVisible({ timeout: 10_000 });
    // This modal is the payoff of the whole drift section — the shadow host that
    // appears mid-series and never resolves to a labelled device. It also loads
    // its per-snapshot history on open, so closing on the dialog merely being
    // visible filmed an empty shell. Wait for the body to fill, then hold long
    // enough to actually read it.
    await expect(ipModal.locator('.spinner-border')).toHaveCount(0, { timeout: 30_000 });
    // The shadow host is the point of the drift section, and the modal is dense
    // — per-snapshot first/last-seen, the role trail, the notes. Give it the
    // long read hold rather than a landing beat.
    await beat(page, READ_HOLD);
    await closeAllModals(page);
    await beat(page, BEAT);
  }

  // The remaining panels are a stop-by, not destinations.
  for (const label of [
    'Baseline Definitions',
    'Subnet Definitions',
    'External Events',
    'Analyst Annotations',
  ]) {
    await gotoSection(page, label);
    await beat(page, FEATURE);
  }

  // Insights close the demo: the LLM correlating the week-7 drop-off with the
  // audit notice. Generated in setup, filmed here. End on it — scrolling to the
  // page bottom afterwards only
  // trades the insight components for footer whitespace as the last thing on
  // screen, and this is the note the eight-week story has been building to.
  await gotoSection(page, 'Network Insights');
  await beat(page, FEATURE);

  timeline.write();
});
