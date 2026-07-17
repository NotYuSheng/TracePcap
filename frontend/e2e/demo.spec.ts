import { test, expect, Page, Locator } from '@playwright/test';
import {
  NETWORK_NAME,
  NETWORK_DESCRIPTION,
  seedWeekFiles,
  seedRoleLabels,
  resetNetwork,
} from './demo-fixture';
import { Timeline } from './demo-timeline';

/**
 * Records the README demo: the Office Audit scenario from docs/sample-files.rst.
 *
 * An auditor is handed eight weekly captures of an office network with no
 * documentation. Over the eight weeks a string of policy violations escalates
 * and then subsides after an audit notice — the demo follows that story rather
 * than touring pages.
 *
 * Not a smoke test: it asserts only enough to fail loudly rather than record a
 * broken or empty UI. Run via `npm run demo:record`, or scripts/record-demo.sh
 * which also encodes the GIF and fast-forwards the LLM waits this logs.
 */

// Pauses are what the viewer reads as pacing, so they are deliberate, not
// arbitrary waits. They are also the main lever on GIF size — the encoded GIF
// costs ~100KB per second of runtime even on a static page, so keep each hold
// as short as still reads clearly.
const BEAT = 1_000;
const READ = 1_800;

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
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 24 });
    await page.waitForTimeout(320);
  }
  await target.click({ timeout: 10_000 });
}

/**
 * Dismiss every open modal and wait for them to actually go. Modals stack here
 * (a role editor over an entity detail), and a lingering backdrop silently
 * swallows the next click on the page underneath.
 */
async function closeAllModals(page: Page) {
  for (let i = 0; i < 3; i++) {
    if (!(await page.getByRole('dialog').first().isVisible().catch(() => false))) break;
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
  }
  await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 5_000 });
}

/**
 * Type at human speed — an instant fill() reads as a glitch on video.
 * Long values are filled instead: typing a 200-character description in real
 * time costs ~6s of GIF for text nobody reads.
 */
async function showType(target: Locator, text: string) {
  await target.click();
  // Clear first: re-runs against an already-labelled entity otherwise interleave
  // into the existing value ("File Server (SMB)File Server (SM…").
  await target.fill('');
  if (text.length > 60) {
    await target.fill(text);
    await target.page().waitForTimeout(200);
  } else {
    await target.pressSequentially(text, { delay: 28 });
  }
}

// Seeding is setup, not story: uploading and analysing eight captures takes
// ~40s each on a cold stack. It lives in beforeAll with its own timeout so the
// recorded test stays short — inside the test body it blew the project timeout
// and closed the browser mid-upload.
let fileIds: Map<string, string>;

test.beforeAll(async ({ request }) => {
  test.setTimeout(15 * 60_000);
  fileIds = await seedWeekFiles(request);
  await resetNetwork(request);

  // Label the known devices up front so the drift panels look like a real
  // audit-in-progress. The file server is skipped — the demo types that one on
  // camera — and 10.0.4.50 stays unlabelled for Suggest with AI.
  await seedRoleLabels(request, fileIds.get('week2_personal_laptop_vpn.pcap')!, [
    '10.0.2.10',
    '10.0.4.50',
  ]);
});

test('README demo walkthrough', async ({ page, request }) => {
  timeline.start();

  // --- Monitor: create the audit network ---------------------------------
  await page.goto('/monitor');
  await expect(page.getByRole('heading', { name: /Network Monitor/i }).first()).toBeVisible();
  await beat(page);

  await showClick(page, page.getByRole('button', { name: /Create Network/i }).first());
  await showType(page.locator('#network-name'), NETWORK_NAME);
  await showType(page.locator('#network-desc'), NETWORK_DESCRIPTION);
  await beat(page);
  // The dialog's own submit button, not the page's "Create Network" trigger.
  await showClick(
    page,
    page.getByRole('dialog').getByRole('button', { name: /^Create Network$/i })
  );

  // Creating a network returns to the list rather than opening it, so click
  // into the new card. It's a clickable Card (no link role) — target its title,
  // and exact-match: a developer's hand-built "Office Audit — Corp HQ" is a
  // prefix of this demo's name and would match a loose selector.
  const card = page.getByText(NETWORK_NAME, { exact: true }).first();
  await expect(card).toBeVisible({ timeout: 15_000 });

  // Attach the eight weekly captures via API before opening the network. Eight
  // rows of file-picker clicks is setup, not story — and adding them after
  // navigating in means filming an empty "No PCAPs added yet" timeline first.
  const networkId = await (async () => {
    const list = await request.get('/api/v1/monitor/networks');
    const nets = await list.json();
    return (Array.isArray(nets) ? nets : (nets.data ?? [])).find(
      (n: { name: string }) => n.name === NETWORK_NAME
    ).id as string;
  })();
  // Each POST computes drift against the previous snapshot, so eight of them is
  // a real pause on an unchanging screen. Race through it.
  await timeline.fastForward('Adding 8 weekly snapshots', 2, async () => {
    for (const [, fileId] of fileIds) {
      const res = await request.post(`/api/v1/monitor/networks/${networkId}/snapshots`, {
        data: { fileId },
      });
      expect(res.ok(), `adding snapshot failed: ${res.status()}`).toBeTruthy();
    }
  });

  await beat(page);
  await showClick(page, card);
  await page.waitForURL(/\/monitor\/[0-9a-f-]{36}/, { timeout: 30_000 });
  await beat(page, READ);

  // --- The story: change events across eight weeks -----------------------
  // The payoff — drift the auditor never had to go looking for. Section anchors
  // are stable ids, unlike the panel headings' text.
  const changes = page.locator('#sec-changes');
  await expect(changes).toBeVisible({ timeout: 15_000 });
  await reveal(changes);
  await beat(page, READ);

  // --- Annotate the file server, then watch the label go stale -----------
  // Step 5/6 of the walkthrough: a confirmed label silently rots as the host's
  // behaviour changes. Carol starts Telnet to this host in week 3.
  await reveal(page.locator('#sec-drift'));
  await beat(page);

  // Clicking an IP badge opens the Entity Detail modal. Roles are per-snapshot,
  // so the modal doesn't edit one directly — each Snapshot History row has a
  // pencil that opens the role editor for that week. That indirection is the
  // point: it's what makes a label able to go stale later.
  const fileServerBadge = page.getByText('10.0.2.10', { exact: true }).first();
  await expect(fileServerBadge).toBeVisible({ timeout: 10_000 });
  await showClick(page, fileServerBadge);

  const entityModal = page.getByRole('dialog');
  await expect(entityModal).toBeVisible({ timeout: 10_000 });
  await beat(page, READ);

  // The per-snapshot table is below the modal's own scroll fold — reveal it, or
  // the pencils aren't rendered to click.
  await reveal(entityModal.getByText('Snapshot History').first());
  await beat(page);

  // One pencil per weekly snapshot, newest first. Target the week-2 row by name
  // rather than index — the walkthrough sets the baseline there, before Carol's
  // Telnet starts in week 3, and the table's sort order is not ours to assume.
  // Select on the title attribute, not the accessible name: the pencil's only
  // child is an <i> icon, so its accessible name computes to "" and
  // getByRole('button', { name: ... }) never matches it.
  //
  // No reveal() either: the table lives in the modal's own scroll container, and
  // centring the row leaves it flush against the container's edge, where
  // showClick's scrollIntoViewIfNeeded then fights that container and times out.
  const week2Pencil = entityModal
    .locator('tbody tr')
    .filter({ hasText: 'week2_personal_laptop_vpn' })
    .first()
    .locator('button[title="Edit role for this snapshot"]');
  await expect(week2Pencil).toBeVisible({ timeout: 10_000 });
  await week2Pencil.click();

  const roleInput = page.getByPlaceholder(/e\.g\. File Server/i);
  await expect(roleInput).toBeVisible({ timeout: 10_000 });
  await showType(roleInput, 'File Server (SMB)');
  await beat(page);
  await showClick(page, page.getByRole('button', { name: /^Save$/i }).last());
  await beat(page, READ);
  // Close both the role editor and the entity modal, and wait for them to go:
  // the next beat clicks a badge on the page underneath, which a lingering
  // modal would swallow.
  await closeAllModals(page);

  // --- Suggest with AI on the unlabelled shadow device -------------------
  // 10.0.4.50 is left unlabelled on purpose (walkthrough Step 5): the LLM has to
  // characterise it from traffic alone — RPi OUI, no hostname, ARP spoofing.
  // Assert rather than skip: wrapped in `if (isVisible)` this beat silently
  // vanished from the GIF for several runs while the test still passed.
  const shadowBadge = page.getByText('10.0.4.50', { exact: true }).first();
  await expect(shadowBadge, 'shadow device 10.0.4.50 not found').toBeVisible({
    timeout: 10_000,
  });
  await showClick(page, shadowBadge);

  // Same indirection as above: open a snapshot's role editor to reach Suggest.
  // The shadow device only appears in weeks 5-6, so take whichever row exists
  // rather than naming a week.
  const shadowModal = page.getByRole('dialog');
  await reveal(shadowModal.getByText('Snapshot History').first());
  await beat(page);
  const shadowEdit = shadowModal
    .locator('tbody tr')
    .first()
    .locator('button[title="Edit role for this snapshot"]');
  await expect(shadowEdit).toBeVisible({ timeout: 10_000 });
  await shadowEdit.click();

  const suggest = page.getByRole('button', { name: /Suggest with AI/i });
  await expect(suggest).toBeVisible({ timeout: 10_000 });
  await showClick(page, suggest);
  // The button relabels to "Suggesting…" while it works, so wait for that to
  // clear rather than for an enabled state that was never lost. The LLM is a
  // reasoning model: tens of seconds. Race through it.
  await timeline.fastForward('Suggest with AI (shadow device)', 2, async () => {
    await expect(page.getByRole('button', { name: /Suggesting…/i })).toBeHidden({
      timeout: 120_000,
    });
  });
  await beat(page, READ);
  await closeAllModals(page);
  await beat(page);

  // --- External event: the audit notice ----------------------------------
  // Step 7 — the real-world event that explains why violations stop in week 7.
  // It feeds the LLM prompt, so it has to exist before Generate Insights below.
  await reveal(page.locator('#sec-external'));
  await beat(page);
  await showClick(page, page.getByRole('button', { name: /Add Event/i }).first());
  // The form is inline in the panel, not a modal — scope to the panel, not a dialog.
  const eventsPanel = page.locator('#sec-external');
  const title = eventsPanel.getByPlaceholder(/Audit notice issued/i);
  await expect(title).toBeVisible({ timeout: 10_000 });
  await showType(title, 'Audit notice issued to staff');
  await beat(page);
  await showClick(page, eventsPanel.getByRole('button', { name: /^(Add Event|Save)$/i }).last());
  await beat(page, READ);

  // --- Generate insights -------------------------------------------------
  // Step 8: with roles and the external event in context, the LLM correlates the
  // week-7 drop-off with the audit notice.
  await reveal(page.locator('#sec-insights'));
  const generate = page.getByRole('button', { name: /Generate Insights|Regenerate/i }).first();
  await expect(generate).toBeVisible({ timeout: 10_000 });
  await showClick(page, generate);
  // Measured ~22s against MiniMax-M2.1 — the single longest wait in the demo.
  // Like Suggest, the button relabels ("Generating…") rather than just disabling.
  await timeline.fastForward('Generate Insights', 2, async () => {
    await expect(page.getByRole('button', { name: /Generating…/i })).toBeHidden({
      timeout: 300_000,
    });
  });
  await beat(page, READ);

  timeline.write();
});
