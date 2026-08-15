import { useEffect, useRef, type RefObject } from 'react';

/**
 * Escape-key ownership for stacked popups (#535).
 *
 * The app has two kinds of dismissible layer:
 *
 *  1. SGDS/react-bootstrap `Modal`s, which already handle Escape themselves — @restart/ui listens
 *     on `document` (bubble phase) and only reacts when its own manager says the modal is topmost,
 *     so Modal-over-Modal already unwinds one layer at a time.
 *  2. Hand-rolled overlays (EntityDetailModal, the conversation tracer, the cluster side panel,
 *     geo-source popovers, CSS-fullscreen graph modes) that react-bootstrap knows nothing about.
 *
 * Before this hook, kind 2 each installed its own `document` keydown listener, so an Escape with
 * both kinds on screen either closed the wrong layer or closed two at once. This module gives
 * kind 2 a single shared LIFO stack and one listener, and teaches it to yield to kind 1:
 *
 *  - Only the **topmost enabled layer** ever handles an Escape — the one painting above the rest,
 *    with registration order as the tiebreak.
 *  - Before it does, it checks whether a foreign (react-bootstrap) modal is stacked **above** it;
 *    if so it stays out of the way and lets react-bootstrap close that modal.
 *  - When it does handle the key it calls `stopImmediatePropagation`, so no react-bootstrap modal
 *    *below* it also closes — one Escape dismisses exactly one layer.
 *
 * Registered layer elements are tagged `data-tp-escape-layer` so the "foreign modal" scan skips
 * them (EntityDetailModal renders with Bootstrap's own `.modal.show` classes).
 */

interface Layer {
  /** Read at dispatch time so a re-rendered closure never re-orders the stack. */
  handler: () => void;
  ref?: RefObject<HTMLElement | null>;
}

/** Every registered layer, in registration order — the tiebreak when stacking cannot separate two. */
const layers: Layer[] = [];

/**
 * Every z-index on the path from the document root down to `el`, outermost first. A raw z-index
 * cannot be compared across stacking contexts — the monitor dialog's fullscreen diagram sets 1080
 * but is nested inside the dialog's own 1055 context, so it does not out-stack a 1070 panel at the
 * document root. The path makes that comparable.
 */
function zIndexPath(el: HTMLElement): number[] {
  const path: number[] = [];
  for (let node: HTMLElement | null = el; node; node = node.parentElement) {
    const z = Number.parseInt(window.getComputedStyle(node).zIndex, 10);
    if (!Number.isNaN(z)) path.unshift(z);
  }
  return path;
}

/**
 * Does `a` paint above `b`? The first z-index the two paths disagree on decides; if neither path
 * disagrees (same context, or one nested inside the other) the later element in document order
 * wins — which is also the right answer for a descendant, since it paints over its own container.
 */
function paintsAbove(a: HTMLElement, b: HTMLElement): boolean {
  const pa = zIndexPath(a);
  const pb = zIndexPath(b);
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
    if (pa[i] !== pb[i]) return pa[i] > pb[i];
  }
  return !!(b.compareDocumentPosition(a) & Node.DOCUMENT_POSITION_FOLLOWING);
}

/** True when a react-bootstrap modal is open above `el` (or, with no `el`, open at all). */
function foreignModalAbove(el: HTMLElement | null | undefined): boolean {
  const foreign = document.querySelectorAll<HTMLElement>(
    '.modal.show:not([data-tp-escape-layer])',
  );
  if (!el) return foreign.length > 0;
  return Array.from(foreign).some(m => paintsAbove(m, el));
}

/**
 * The layer that owns Escape: the one painting above all the others. Registration order is the
 * tiebreak (and the whole answer for layers that registered no element), so a layer opened later
 * still wins when nothing separates them visually.
 */
function topLayer(): Layer | undefined {
  let top: Layer | undefined;
  for (const layer of layers) {
    const challenger = layer.ref?.current;
    const incumbent = top?.ref?.current;
    if (!top || !challenger || !incumbent || paintsAbove(challenger, incumbent)) top = layer;
  }
  return top;
}

function onKeyDown(e: KeyboardEvent): void {
  if (e.key !== 'Escape' || e.defaultPrevented) return;

  // An open info popover is always the topmost thing on screen. Every `OverlayTrigger` in the app
  // is click-triggered with `rootClose`, and @restart/ui dismisses those on Escape *keyup* — so
  // swallowing the keydown leaves the popover to close itself while sparing the modal underneath,
  // which would otherwise close in the same press.
  if (document.querySelector('.popover.show')) {
    e.preventDefault();
    e.stopImmediatePropagation();
    return;
  }

  const top = topLayer();
  if (!top) return;
  if (foreignModalAbove(top.ref?.current)) return;
  e.preventDefault();
  // Capture phase, so this also pre-empts react-bootstrap's document listener for any modal
  // sitting *below* this layer — without it, one Escape would close two layers.
  e.stopImmediatePropagation();
  top.handler();
}

/**
 * The listener is shared by every layer plus the app-root guard, so it is reference-counted rather
 * than tied to the stack being non-empty: the popover rule above has to work on pages that have no
 * hand-rolled layer at all.
 */
let listeners = 0;

function retainListener(): void {
  listeners += 1;
  // Re-adding an identical listener is a no-op, so an unbalanced release can never leave the
  // coordinator deaf.
  document.addEventListener('keydown', onKeyDown, true);
}

function releaseListener(): void {
  listeners = Math.max(0, listeners - 1);
  if (listeners === 0) document.removeEventListener('keydown', onKeyDown, true);
}

function addLayer(layer: Layer): void {
  layers.push(layer);
  layer.ref?.current?.setAttribute('data-tp-escape-layer', '');
  retainListener();
}

function removeLayer(layer: Layer): void {
  const i = layers.indexOf(layer);
  if (i !== -1) layers.splice(i, 1);
  layer.ref?.current?.removeAttribute('data-tp-escape-layer');
  releaseListener();
}

/**
 * Mount once at the app root. Keeps the shared Escape listener alive for the whole session so the
 * "an open popover owns Escape" rule holds even when no hand-rolled layer is registered.
 */
export function useEscapeLayerRoot(): void {
  useEffect(() => {
    retainListener();
    return () => releaseListener();
  }, []);
}

interface EscapeLayerOptions {
  /** Set false while the layer is on the page but not dismissible (e.g. not fullscreen yet). */
  enabled?: boolean;
  /**
   * The layer's overlay element. Used to decide whether a react-bootstrap modal is stacked above
   * it. Omit only for layers that can never have a modal opened over them — without it the layer
   * defers to *any* open modal.
   */
  ref?: RefObject<HTMLElement | null>;
}

/**
 * Closes this layer when Escape is pressed, but only while it is the topmost dismissible layer.
 * Pass the overlay element's ref so stacking against SGDS modals can be resolved.
 */
export function useEscapeLayer(
  onEscape: () => void,
  { enabled = true, ref }: EscapeLayerOptions = {},
): void {
  // The handler is read through a ref so re-renders never unregister/re-register the layer —
  // that would silently promote a parent past its own child in the registration tiebreak.
  const handlerRef = useRef(onEscape);
  useEffect(() => {
    handlerRef.current = onEscape;
  });

  useEffect(() => {
    if (!enabled) return;
    const layer: Layer = { handler: () => handlerRef.current(), ref };
    addLayer(layer);
    return () => removeLayer(layer);
  }, [enabled, ref]);
}

/** Test-only: drop every registered layer so one test cannot leak into the next. */
export function __resetEscapeLayers(): void {
  layers.length = 0;
  listeners = 0;
  document.removeEventListener('keydown', onKeyDown, true);
}
