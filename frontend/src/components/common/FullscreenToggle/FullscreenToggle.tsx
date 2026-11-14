import { useEffect, useMemo, useRef, useState, type RefObject } from 'react';
import { useEscapeLayer } from '@utils/useEscapeLayer';
import { Button, Overlay } from '@govtechsg/sgds-react';
import './FullscreenToggle.css';

interface Props {
  isFullscreen: boolean;
  onToggle: () => void;
  /**
   * Bumped when the user seems to be hunting for this button: the graph's Fit view pressed again
   * with nothing left to fit. Each bump points the user here with a short hint.
   */
  hintSignal?: number;
  /** A unique id for the hint popover, needed when more than one graph is on the page. */
  hintId?: string;
}

const HINT_MS = 6000;

/** The graph card's fullscreen button, which can point itself out to a user looking for it. */
export function FullscreenToggle({
  isFullscreen,
  onToggle,
  hintSignal = 0,
  hintId = 'fullscreen-hint',
}: Props) {
  // The hint anchors on a wrapper: SGDS Button doesn't forward its ref.
  const target = useRef<HTMLSpanElement>(null);
  const [hint, setHint] = useState(false);

  useEffect(() => {
    if (hintSignal === 0) return;
    setHint(true);
    const hide = setTimeout(() => setHint(false), HINT_MS);
    return () => clearTimeout(hide);
  }, [hintSignal]);

  const layerRef = useMemo(
    () =>
      ({
        get current() {
          return document.getElementById(hintId);
        },
      }) as RefObject<HTMLElement | null>,
    [hintId]
  );
  useEscapeLayer(() => setHint(false), { enabled: hint, ref: layerRef });

  const label = isFullscreen ? 'Exit fullscreen' : 'Fullscreen';
  return (
    <>
      <span ref={target} className="d-inline-flex">
        <Button
          variant="link"
          size="sm"
          className={`p-0 text-muted${hint ? ' fullscreen-toggle-pulse' : ''}`}
          onClick={() => {
            setHint(false);
            onToggle();
          }}
          aria-label={label}
          title={label}
        >
          <i
            className={`bi ${isFullscreen ? 'bi-fullscreen-exit' : 'bi-fullscreen'}`}
            aria-hidden="true"
          />
        </Button>
      </span>
      {/* A status note, not a popover: no rootClose, so further clicks (another Fit view press)
          don't dismiss it. It goes on a timer, on Escape (the shared layer stack) or on pressing
          the button. */}
      <Overlay target={target} show={hint} placement="bottom-end">
        {overlay => (
          <div
            ref={overlay.ref}
            style={overlay.style}
            id={hintId}
            role="status"
            className="fullscreen-hint"
          >
            {isFullscreen ? (
              <>
                To leave fullscreen, use this button. <strong>Fit view</strong> only re-centres the
                graph.
              </>
            ) : (
              <>
                Looking for fullscreen? It's this button. <strong>Fit view</strong>, at the bottom
                right of the graph, only re-centres it.
              </>
            )}
          </div>
        )}
      </Overlay>
    </>
  );
}
