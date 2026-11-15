/**
 * Draws the network map for the PDF report (#1152): the Network tab's grouped layout (your
 * networks, servers, the internet), in light colours, as a JPEG small enough to send.
 *
 * The map is the real NetworkGraph, rendered into a container that is on screen but covered by a
 * scrim, then captured with html-to-image (see captureNetworkDiagrams.ts for why it can't be
 * hidden any other way). Its on-screen controls are hidden; its legend's icon-font glyphs (which
 * html-to-image can't embed) are drawn as coloured dots.
 *
 * "As you left it" passes the Network tab's filtered nodes and edges; "the whole capture" builds
 * them here with the same hook the Network tab uses, so both group and name hosts the same way.
 */

import { createRoot } from 'react-dom/client';
import { toJpeg } from 'html-to-image';
import type { DeviceLink, GraphEdge, GraphNode } from '@/features/network/types';
import type { AnalysisSummary } from '@/types';
import { loadGrouping } from './reportMapGrouping';
import { GroupedMap, WholeCaptureMap } from './ReportMapViews';

const CAPTURE_W = 1400;
const CAPTURE_H = 860;
/** Twice the CSS size: sharp when printed 18 cm wide, about 1 MB as a JPEG. */
const PIXEL_RATIO = 2;
/** The legend strip under the map. */
const LEGEND_H = 46;
const TIMEOUT_MS = 60_000;

export interface MapSource {
  fileId: string;
  networkId?: string;
  summary?: AnalysisSummary;
  /** The Network tab's nodes and edges as left; absent for the whole capture. */
  shown?: { nodes: GraphNode[]; edges: GraphEdge[]; deviceLinks?: DeviceLink[] };
}

/** The map as a base64 JPEG (no data: prefix), or null when the capture has nothing to draw. */
export async function captureNetworkMap(source: MapSource): Promise<string | null> {
  const grouping = await loadGrouping(source.fileId);

  return new Promise((resolve, reject) => {
    const id = `__report-map-${Date.now()}`;
    const overlay = document.createElement('div');
    overlay.style.cssText =
      'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,0.55);pointer-events:none';
    const container = document.createElement('div');
    container.id = id;
    container.style.cssText = [
      'position:fixed',
      'top:0',
      'left:0',
      `width:${CAPTURE_W}px`,
      `height:${CAPTURE_H}px`,
      'z-index:9999',
      'overflow:hidden',
      'background:#fff',
    ].join(';');
    // Fill the capture area, no buttons, and the legend as a strip under the map rather than over
    // it; its icons as dots (the icon font can't be embedded).
    const styleEl = document.createElement('style');
    styleEl.textContent = `
      #${id} .network-graph-wrapper { height:${CAPTURE_H}px !important; }
      #${id} .network-graph-canvas, #${id} .network-graph-groups, #${id} .network-graph-particles {
        bottom:${LEGEND_H}px !important; }
      #${id} .ng-overlay-controls, #${id} .ng-layouting { display:none !important; }
      #${id} .ng-legend { left:0 !important; right:0 !important; bottom:0 !important; top:auto !important;
        height:${LEGEND_H}px; box-sizing:border-box; flex-direction:row !important; flex-wrap:wrap;
        align-items:center; align-content:center; gap:4px 16px !important; border-radius:0 !important;
        border:0 !important; border-top:1px solid #e4e7ec !important; background:#fff !important; }
      #${id} .ng-legend-divider { width:1px; height:14px; margin:0 4px; }
      #${id} .ng-legend-icon { font-size:0 !important; width:9px; height:9px; display:inline-block;
        border-radius:50%; background:currentColor; vertical-align:middle; }
      #${id} .ng-legend-icon::before { content:none !important; }
    `;
    document.head.appendChild(styleEl);
    document.body.appendChild(overlay);
    document.body.appendChild(container);

    const root = createRoot(container);
    let settled = false;
    const cleanup = () => {
      root.unmount();
      container.remove();
      overlay.remove();
      styleEl.remove();
    };
    const finish = (value: string | null, err?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (err) reject(err);
      else resolve(value);
    };
    const onReady = () => {
      if (settled) return;
      // Let Sigma finish its paint passes before the snapshot.
      setTimeout(
        () =>
          requestAnimationFrame(async () => {
            try {
              const url = await toJpeg(container, {
                width: CAPTURE_W,
                height: CAPTURE_H,
                pixelRatio: PIXEL_RATIO,
                quality: 0.86,
                backgroundColor: '#ffffff',
                skipFonts: true,
              });
              finish(url.split(',')[1]);
            } catch (e) {
              finish(null, e instanceof Error ? e : new Error(String(e)));
            }
          }),
        700
      );
    };
    const onEmpty = () => finish(null);
    const onError = (e: Error) => finish(null, e);

    root.render(
      source.shown ? (
        <GroupedMap
          nodes={source.shown.nodes}
          edges={source.shown.edges}
          deviceLinks={source.shown.deviceLinks}
          grouping={grouping}
          onReady={onReady}
          onEmpty={onEmpty}
        />
      ) : (
        <WholeCaptureMap
          fileId={source.fileId}
          summary={source.summary}
          networkId={source.networkId}
          grouping={grouping}
          onReady={onReady}
          onEmpty={onEmpty}
          onError={onError}
        />
      )
    );
    setTimeout(() => finish(null, new Error('Drawing the network map timed out')), TIMEOUT_MS);
  });
}
