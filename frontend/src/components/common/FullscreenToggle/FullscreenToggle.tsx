import { useEffect, useMemo, useRef, useState, type RefObject } from 'react';
import { Button, Overlay, Popover } from '@govtechsg/sgds-react';
import { useEscapeLayer } from '@utils/useEscapeLayer';
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
export function FullscreenToggle({ isFullscreen, onToggle, hintSignal = 0, hintId = 'fullscreen-hint' }: Props) {
  const target = useRef<HTMLButtonElement>(null);
  const [hint, setHint] = useState(false);

  useEffect(() => {
    if (hintSignal === 0) return;
    setHint(true);
    const t = setTimeout(() => setHint(false), HINT_MS);
    return () => clearTimeout(t);
  }, [hintSignal]);

  const layerRef = useMemo(
    () => ({ get current() { return document.getElementById(hintId); } }) as RefObject<HTMLElement | null>,
    [hintId],
  );
  useEscapeLayer(() => setHint(false), { enabled: hint, ref: layerRef });

  const label = isFullscreen ? 'Exit fullscreen' : 'Fullscreen';
  return (
    <>
      <Button
        ref={target}
        variant="link"
        size="sm"
        className={`p-0 text-muted${hint ? ' fullscreen-toggle-pulse' : ''}`}
        onClick={() => { setHint(false); onToggle(); }}
        aria-label={label}
        title={label}
      >
        <i className={`bi ${isFullscreen ? 'bi-fullscreen-exit' : 'bi-fullscreen'}`} aria-hidden="true" />
      </Button>
      <Overlay target={target.current} show={hint} placement="bottom-end" rootClose onHide={() => setHint(false)}>
        <Popover id={hintId} className="fullscreen-hint">
          <Popover.Body>
            {isFullscreen ? (
              <>To leave fullscreen, use this button. <strong>Fit view</strong> only re-centres the graph.</>
            ) : (
              <>Looking for fullscreen? It's this button. <strong>Fit view</strong>, at the bottom right of the graph, only re-centres it.</>
            )}
          </Popover.Body>
        </Popover>
      </Overlay>
    </>
  );
}
