import { useEffect, useState, type MutableRefObject } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { SideDrawer } from '@components/common/SideDrawer';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { AnalysisData } from '@/types';
import type { NetworkGraphState } from '@/pages/Analysis/AnalysisPage';
import { captureNetworkMap } from './captureNetworkMap';
import {
  BRIEFING,
  ROWS,
  mapCaption,
  sectionsFor,
  type ReportKind,
  type ReportSection,
} from './reportSections';
import './ReportDrawer.css';

interface ReportDrawerProps {
  show: boolean;
  onHide: () => void;
  fileId: string;
  fileName: string;
  networkId?: string;
  summary?: AnalysisData;
  /** Whether the Story tab has a story for this capture. */
  hasStory: boolean;
  /** The Network tab's graph as left; empty until the tab has been opened. */
  graphStateRef: MutableRefObject<NetworkGraphState>;
}

interface MemoryError {
  message: string;
  attemptedSizeMb: number;
  recommendedAppMemoryMb: number | null;
}

/**
 * Download report (#1152): choose the briefing or the full report, adjust its parts, and which
 * network map goes in, then build the PDF. Progress shows in the footer.
 */
export function ReportDrawer({
  show,
  onHide,
  fileId,
  fileName,
  networkId,
  summary,
  hasStory,
  graphStateRef,
}: ReportDrawerProps) {
  const [extraction, setExtraction] = useState<boolean | null>(null);
  const [kind, setKind] = useState<ReportKind>('briefing');
  const [chosen, setChosen] = useState<Set<ReportSection>>(new Set(BRIEFING));
  const [mapMode, setMapMode] = useState<'asLeft' | 'whole'>('whole');
  const [step, setStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [memoryError, setMemoryError] = useState<MemoryError | null>(null);

  const visited = graphStateRef.current.filteredNodes.length > 0;
  const filters = graphStateRef.current.activeFilterLabels;

  // Whether extraction ran, so "Extracted files" can say why it's off.
  useEffect(() => {
    if (!show) return;
    let live = true;
    apiClient
      .get<{ enableFileExtraction?: boolean }>(API_ENDPOINTS.FILE_METADATA(fileId))
      .then(r => live && setExtraction(r.data.enableFileExtraction !== false))
      .catch(() => live && setExtraction(true));
    return () => {
      live = false;
    };
  }, [show, fileId]);

  const unavailable = new Set<ReportSection>();
  if (!hasStory) unavailable.add('STORY');
  if (extraction === false) unavailable.add('EXTRACTED_FILES');
  const why: Partial<Record<ReportSection, string>> = {
    STORY: 'Not written yet',
    EXTRACTED_FILES: 'Extraction was off',
  };

  // Opening starts from the briefing, the map as left when the Network tab was used.
  useEffect(() => {
    if (!show) return;
    setKind('briefing');
    setChosen(sectionsFor('briefing', unavailable));
    setMapMode(visited ? 'asLeft' : 'whole');
    setError(null);
    setMemoryError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show]);
  useEffect(() => {
    setChosen(prev => new Set([...prev].filter(s => !unavailable.has(s))));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasStory, extraction]);

  const pickKind = (k: ReportKind) => {
    setKind(k);
    setChosen(sectionsFor(k, unavailable));
  };
  const toggle = (s: ReportSection) =>
    setChosen(prev => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  const busy = step !== null;

  const download = async () => {
    setError(null);
    setMemoryError(null);
    try {
      let mapImage: string | null = null;
      let caption: string | null = null;
      if (chosen.has('MAP')) {
        setStep('Drawing the network map…');
        const asLeft = mapMode === 'asLeft' && visited;
        const state = graphStateRef.current;
        mapImage = await captureNetworkMap({
          fileId,
          networkId,
          summary,
          shown: asLeft
            ? { nodes: state.filteredNodes, edges: state.filteredEdges, deviceLinks: state.deviceLinks }
            : undefined,
        });
        caption = mapCaption(asLeft, state.activeFilterLabels, state.nodeLimitNote);
      }
      setStep('Building the PDF…');
      const order = ROWS.map(r => r.key).filter(k => chosen.has(k));
      const response = await apiClient.post(
        API_ENDPOINTS.REPORT_DOWNLOAD(fileId),
        { sections: order, mapImage, mapCaption: caption, networkId },
        { responseType: 'blob' }
      );
      const url = URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `${fileName.replace(/\.[^.]+$/, '')} report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      onHide();
    } catch (e) {
      console.error('Report generation failed', e);
      // The request asks for a blob, so a JSON error body arrives as one too.
      const raw = (e as { response?: { data?: unknown } })?.response?.data;
      let data: Record<string, unknown> = {};
      if (raw instanceof Blob) {
        try {
          data = JSON.parse(await raw.text());
        } catch {
          // Not JSON (e.g. a proxy's error page).
        }
      } else if (raw && typeof raw === 'object') {
        data = raw as Record<string, unknown>;
      }
      if (data.errorCode === 'PAYLOAD_STRING_TOO_LARGE') {
        setMemoryError({
          message: (data.message as string) ?? 'The network map was too large to include.',
          attemptedSizeMb: (data.attemptedSizeMb as number) ?? 0,
          recommendedAppMemoryMb: (data.recommendedAppMemoryMb as number | null) ?? null,
        });
      } else {
        setError(e instanceof Error && !raw ? e.message : 'The report couldn’t be built. Try again.');
      }
    } finally {
      setStep(null);
    }
  };

  return (
    <SideDrawer
      show={show}
      onHide={busy ? () => undefined : onHide}
      title="Download report"
      titleId="report-drawer-title"
      footer={
        <div className="report-drawer-footer">
          <span className="text-muted small" aria-live="polite">
            {step ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                {step}
              </>
            ) : null}
          </span>
          <Button variant="outline-secondary" size="sm" onClick={onHide} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" size="sm" onClick={download} disabled={busy || chosen.size === 0}>
            <i className="bi bi-file-earmark-pdf me-1" aria-hidden="true" />
            Download PDF
          </Button>
        </div>
      }
    >
      {error && (
        <Alert variant="danger" className="mb-3" dismissible onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {memoryError && (
        <Alert variant="danger" className="mb-3" dismissible onClose={() => setMemoryError(null)}>
          <p className="mb-1 fw-semibold">The report is too large for this deployment</p>
          <p className="mb-0 small">
            The network map was <strong>{memoryError.attemptedSizeMb} MB</strong>.{' '}
            {memoryError.recommendedAppMemoryMb ? (
              <>
                Raise <code>APP_MEMORY_MB</code> to at least{' '}
                <strong>{memoryError.recommendedAppMemoryMb}</strong> and restart the backend, or
                leave the map out.
              </>
            ) : (
              memoryError.message
            )}
          </p>
        </Alert>
      )}

      <fieldset className="report-drawer-group" disabled={busy}>
        <legend>How much</legend>
        <ReportChoice
          name="report-kind"
          checked={kind === 'briefing'}
          onChange={() => pickKind('briefing')}
          title="Briefing"
          detail="What needs a look, the hosts by network and the map. For someone who won’t open TracePcap."
        />
        <ReportChoice
          name="report-kind"
          checked={kind === 'full'}
          onChange={() => pickKind('full')}
          title="Full"
          detail="The briefing, then traffic, conversations, extracted files and an appendix of every flagged conversation."
        />
      </fieldset>

      <fieldset className="report-drawer-group" disabled={busy}>
        <legend>Include</legend>
        {ROWS.map(r => {
          const off = unavailable.has(r.key);
          return (
            <div key={r.key} className={`report-drawer-row${off ? ' is-off' : ''}`}>
              <Form.Check
                type="checkbox"
                id={`report-${r.key}`}
                label={r.label}
                checked={chosen.has(r.key)}
                disabled={off}
                onChange={() => toggle(r.key)}
              />
              <span className="report-drawer-hint">{off ? why[r.key] : r.hint}</span>
            </div>
          );
        })}
      </fieldset>

      {chosen.has('MAP') && (
        <fieldset className="report-drawer-group" disabled={busy}>
          <legend>Network map</legend>
          <ReportChoice
            name="report-map"
            checked={mapMode === 'asLeft' && visited}
            disabled={!visited}
            onChange={() => setMapMode('asLeft')}
            title="As you left it"
            detail={
              visited
                ? filters.length
                  ? `With your filters: ${filters.join(' · ')}`
                  : 'No filters set'
                : 'Open the Network tab first to set filters'
            }
          />
          <ReportChoice
            name="report-map"
            checked={mapMode === 'whole' || !visited}
            onChange={() => setMapMode('whole')}
            title="The whole capture"
            detail="Every host, ignoring the Network tab’s filters"
          />
        </fieldset>
      )}
    </SideDrawer>
  );
}

function ReportChoice({
  name,
  checked,
  disabled,
  onChange,
  title,
  detail,
}: {
  name: string;
  checked: boolean;
  disabled?: boolean;
  onChange: () => void;
  title: string;
  detail: string;
}) {
  return (
    <label className={`report-drawer-choice${checked ? ' is-on' : ''}${disabled ? ' is-off' : ''}`}>
      <input type="radio" name={name} checked={checked} disabled={disabled} onChange={onChange} />
      <span>
        <b>{title}</b>
        <span className="report-drawer-hint d-block">{detail}</span>
      </span>
    </label>
  );
}
