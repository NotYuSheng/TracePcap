import { useEffect, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import {
  adjudicationService,
  type AdjudicationOverride,
  type AdjudicationEvidence,
} from '@/features/insights/services/adjudicationService';
import { currentUsername } from '@/auth/tokenStore';

/** One candidate answer with the reasons that voted for it. */
export interface AdjudicationCandidate {
  label: string;
  source: string;
  score: number;
  reasons?: string[];
}

/** The current adjudicated verdict, as the caller already has it (e.g. from the host-identity read). */
export interface AdjudicationVerdict {
  label: string;
  basis: 'HUMAN' | 'MACHINE';
  /** 0-100 when this verdict is scored; undefined for axes that aren't (e.g. Service/Behaviour). */
  confidence?: number;
  contested: boolean;
  candidates?: AdjudicationCandidate[];
}

interface Props {
  fileId: string;
  /** The backend Adjudicator.question() key, e.g. "host-identity". */
  question: string;
  entityKey: string;
  /** Human-friendly heading, e.g. "Identity". */
  title: string;
  verdict: AdjudicationVerdict;
  /** Called after an override/evidence change so the parent can re-fetch the verdict. */
  onChanged: () => void;
  /**
   * Predefined label choices for override/evidence. When set, those fields become a dropdown of
   * these options plus "Other…" (free text); when omitted they stay free-text. (#499)
   */
  labelOptions?: string[];
  /**
   * Z-index of the surrounding panel/modal, so the add-evidence modal can render above it. Needed in
   * monitor mode where NodeDetails is itself a raised modal (modal-in-modal).
   */
  zIndex?: number;
}

/** A label input that is a dropdown of known options + "Other…" free-text, or plain text if none. */
function LabelField({
  value,
  onChange,
  options,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  options?: string[];
  placeholder: string;
}) {
  const OTHER = '__other__';
  // In "Other" mode when the current value isn't one of the known options.
  const isOther = !!value && options != null && !options.includes(value);
  const [mode, setMode] = useState<string>(isOther ? OTHER : value);
  if (!options || options.length === 0) {
    return (
      <Form.Control size="sm" className="mb-2" placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)} />
    );
  }
  return (
    <>
      <Form.Select
        size="sm"
        className="mb-2"
        value={mode}
        onChange={e => {
          const v = e.target.value;
          setMode(v);
          onChange(v === OTHER ? '' : v);
        }}
      >
        <option value="">Select a label…</option>
        {options.map(o => (
          <option key={o} value={o}>{o}</option>
        ))}
        <option value={OTHER}>Other…</option>
      </Form.Select>
      {mode === OTHER && (
        <Form.Control size="sm" className="mb-2" placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)} />
      )}
    </>
  );
}

/**
 * One panel for any adjudicated question (adjudication explainability): the verdict, WHY (candidates
 * + reasons), a human override ("I disagree"), analyst evidence-append, and the audit trail. Keyed
 * by `question`, so the same component serves host-identity today and any future adjudicated
 * question with no changes.
 */
export function AdjudicationPanel({ fileId, question, entityKey, title, verdict, onChanged, labelOptions, zIndex }: Props) {
  const [override, setOverride] = useState<AdjudicationOverride | null>(null);
  const [evidence, setEvidence] = useState<AdjudicationEvidence[]>([]);
  const [loading, setLoading] = useState(true);

  const [overriding, setOverriding] = useState(false);
  const [overrideLabel, setOverrideLabel] = useState('');
  const [overrideRationale, setOverrideRationale] = useState('');

  const [addingEvidence, setAddingEvidence] = useState(false);
  const [evLabel, setEvLabel] = useState('');
  const [evWeight, setEvWeight] = useState(40);
  const [evReason, setEvReason] = useState('');
  // Id of the evidence being edited (reuses the add-evidence modal); null = adding new.
  const [editingEvidenceId, setEditingEvidenceId] = useState<number | null>(null);

  const [busy, setBusy] = useState(false);

  // Author of the current session — only the author of a piece of evidence may edit/delete it.
  const me = currentUsername();

  const refresh = () => {
    setLoading(true);
    Promise.all([
      adjudicationService.getOverride(fileId, question, entityKey),
      adjudicationService.listEvidence(fileId, question, entityKey),
    ])
      .then(([o, ev]) => {
        setOverride(o);
        setEvidence(ev);
      })
      .finally(() => setLoading(false));
  };

  useEffect(refresh, [fileId, question, entityKey]);

  const handleSaveOverride = async () => {
    if (!overrideLabel.trim()) return;
    setBusy(true);
    try {
      await adjudicationService.setOverride(fileId, question, entityKey, overrideLabel.trim(), overrideRationale.trim() || undefined);
      setOverriding(false);
      setOverrideLabel('');
      setOverrideRationale('');
      refresh();
      onChanged();
    } finally {
      setBusy(false);
    }
  };

  /** Resolve a contested verdict by confirming one candidate — a hard human override that both sets
   *  the label and clears the contested flag (#499). */
  const handleResolve = async (label: string) => {
    setBusy(true);
    try {
      await adjudicationService.setOverride(fileId, question, entityKey, label, 'Resolved a contested verdict');
      refresh();
      onChanged();
    } finally {
      setBusy(false);
    }
  };

  const handleClearOverride = async () => {
    setBusy(true);
    try {
      await adjudicationService.clearOverride(fileId, question, entityKey);
      refresh();
      onChanged();
    } finally {
      setBusy(false);
    }
  };

  const resetEvidenceForm = () => {
    setAddingEvidence(false);
    setEditingEvidenceId(null);
    setEvLabel('');
    setEvReason('');
    setEvWeight(40);
  };

  const handleSaveEvidence = async () => {
    if (!evLabel.trim() || !evReason.trim()) return;
    setBusy(true);
    try {
      if (editingEvidenceId != null) {
        await adjudicationService.updateEvidence(
          fileId, question, entityKey, editingEvidenceId, evLabel.trim(), evWeight, evReason.trim());
      } else {
        await adjudicationService.appendEvidence(
          fileId, question, entityKey, evLabel.trim(), evWeight, evReason.trim());
      }
      resetEvidenceForm();
      refresh();
      onChanged();
    } finally {
      setBusy(false);
    }
  };

  const handleEditEvidence = (ev: AdjudicationEvidence) => {
    setEditingEvidenceId(ev.id);
    setEvLabel(ev.label);
    setEvWeight(ev.weight);
    setEvReason(ev.reason);
    setAddingEvidence(true);
  };

  const handleDeleteEvidence = async (ev: AdjudicationEvidence) => {
    setBusy(true);
    try {
      await adjudicationService.deleteEvidence(fileId, question, entityKey, ev.id);
      refresh();
      onChanged();
    } finally {
      setBusy(false);
    }
  };

  const attributed = (actor: string) => (actor && actor !== 'system' ? actor : 'an analyst');

  return (
    <div className="mb-4">
      <h6 className="border-bottom pb-1 mb-2 d-flex align-items-center justify-content-between">
        <span>{title}</span>
        {!loading && !override && !overriding && (
          <Button
            variant="outline-secondary"
            size="sm"
            className="py-0"
            style={{ fontSize: '0.75rem' }}
            onClick={() => { setOverriding(true); setOverrideLabel(''); }}
          >
            <i className="bi bi-pencil me-1" />I disagree
          </Button>
        )}
      </h6>

      {loading && <div className="text-muted small fst-italic">Loading…</div>}

      {!loading && (
        <>
          {/* Verdict badge */}
          <div className="mb-2">
            <span
              className={`badge ${override ? 'bg-primary' : verdict.contested ? 'bg-warning text-dark' : verdict.basis === 'HUMAN' ? 'bg-primary' : 'bg-secondary'}`}
              title={
                override
                  ? `Overridden by ${attributed(override.actor)}`
                  : verdict.contested
                    ? 'Contested — the candidates below disagree'
                    : verdict.basis === 'HUMAN'
                      ? 'Confirmed by an analyst'
                      : verdict.confidence != null
                        ? `Adjudicated from classification (confidence ${verdict.confidence}%)`
                        : 'Adjudicated from classification'
              }
            >
              {(override || verdict.basis === 'HUMAN') ? '✓ ' : ''}
              {/* An override wins the label outright — show what the analyst chose, not the stale
                  machine verdict (the per-axis panels don't re-fetch their verdict). */}
              {override ? override.label : verdict.label}
              {verdict.contested && !override ? ' ⚠ contested' : ''}
            </span>
            {!override && verdict.basis === 'MACHINE' && verdict.confidence != null && (
              <span className="text-muted ms-2" style={{ fontSize: '0.72rem' }}>
                {verdict.confidence}% confidence
              </span>
            )}
          </div>

          {/* Contested → the analyst validates the discrepancy by confirming a winner. Picking one
              becomes a hard human override, which resolves the label and clears the flag (#499). */}
          {verdict.contested && !override && (
            <Alert variant="warning" className="p-2 mb-2 small">
              <div className="mb-1">
                <i className="bi bi-exclamation-triangle me-1" />
                <strong>Contested</strong> — the signals disagree. Confirm the correct answer:
              </div>
              <div className="d-flex flex-wrap gap-1">
                {(verdict.candidates && verdict.candidates.length > 0
                  ? verdict.candidates.map(c => c.label)
                  : [verdict.label]
                ).map(label => (
                  <Button
                    key={label}
                    variant="outline-primary"
                    size="sm"
                    className="py-0"
                    style={{ fontSize: '0.72rem' }}
                    onClick={() => handleResolve(label)}
                    disabled={busy}
                  >
                    <i className="bi bi-check2 me-1" />{label}
                  </Button>
                ))}
                {/* None of the candidates is right — set a different answer via the override editor. */}
                <Button
                  variant="outline-secondary"
                  size="sm"
                  className="py-0"
                  style={{ fontSize: '0.72rem' }}
                  onClick={() => { setOverriding(true); setOverrideLabel(''); }}
                  disabled={busy}
                >
                  <i className="bi bi-pencil me-1" />Other…
                </Button>
              </div>
            </Alert>
          )}

          {/* Stale carried-forward override (#499 monitor mode): the evidence drifted since the
              analyst set this override on a prior snapshot — they should re-validate it. */}
          {override?.staleSince && (
            <Alert variant="warning" className="p-2 mb-2 small">
              <div>
                <i className="bi bi-exclamation-triangle me-1" />
                <strong>Stale</strong> — evidence changed since this was set
                {override.staleFields && override.staleFields.length > 0 && (
                  <>: {override.staleFields.join('; ')}</>
                )}
                . Re-affirm with “I disagree” or revert to the machine verdict.
              </div>
            </Alert>
          )}

          {/* Override state + clear */}
          {override && (
            <Alert variant="info" className="p-2 mb-2 small">
              <div>
                <i className="bi bi-person-check me-1" />
                Overridden by <strong>{attributed(override.actor)}</strong>
                {override.rationale && <>: {override.rationale}</>}
              </div>
              <Button
                variant="link"
                size="sm"
                className="p-0 mt-1 text-muted"
                style={{ fontSize: '0.72rem' }}
                onClick={handleClearOverride}
                disabled={busy}
              >
                <i className="bi bi-arrow-counterclockwise me-1" />Revert to machine verdict
              </Button>
            </Alert>
          )}

          {/* Override editor */}
          {overriding && (
            <div className="mb-2 p-2 rounded border">
              <LabelField
                value={overrideLabel}
                onChange={setOverrideLabel}
                options={labelOptions}
                placeholder="Correct label (e.g. Domain Controller)"
              />
              <Form.Control
                as="textarea"
                size="sm"
                rows={2}
                className="mb-2"
                placeholder="Why (optional)"
                value={overrideRationale}
                onChange={e => setOverrideRationale(e.target.value)}
              />
              <div className="d-flex gap-2">
                <Button variant="primary" size="sm" className="py-0" style={{ fontSize: '0.75rem' }} onClick={handleSaveOverride} disabled={busy || !overrideLabel.trim()}>
                  {busy ? <><Spinner size="sm" className="me-1" />Saving…</> : <><i className="bi bi-floppy me-1" />Save override</>}
                </Button>
                <Button variant="outline-secondary" size="sm" className="py-0" style={{ fontSize: '0.75rem' }} onClick={() => setOverriding(false)} disabled={busy}>
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {/* Why — candidates + reasons */}
          {verdict.candidates && verdict.candidates.length > 0 && (
            <div className="mb-2">
              <div className="text-muted mb-1" style={{ fontSize: '0.72rem', fontWeight: 600 }}>Why</div>
              {verdict.candidates.map(c => (
                <div key={c.label} style={{ fontSize: '0.72rem' }} className="mb-1">
                  <span className="fw-semibold">{c.label}</span>
                  <span className="text-muted"> ({c.score})</span>
                  {(c.reasons?.length ?? 0) > 0 && (
                    <ul className="mb-0 ps-3 text-muted">
                      {c.reasons!.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Evidence trail + add */}
          <div>
            <div className="d-flex align-items-center justify-content-between">
              <span className="text-muted" style={{ fontSize: '0.72rem', fontWeight: 600 }}>
                Analyst evidence{evidence.length > 0 ? ` (${evidence.length})` : ''}
              </span>
              {!addingEvidence && (
                <Button
                  variant="link"
                  size="sm"
                  className="p-0 text-muted"
                  style={{ fontSize: '0.72rem' }}
                  onClick={() => { setEditingEvidenceId(null); setEvLabel(''); setEvWeight(40); setEvReason(''); setAddingEvidence(true); }}
                >
                  <i className="bi bi-plus-circle me-1" />Add evidence
                </Button>
              )}
            </div>

            {evidence.length > 0 ? (
              <ul className="mb-1 ps-3 text-muted" style={{ fontSize: '0.72rem' }}>
                {evidence.map(ev => (
                  <li key={ev.id}>
                    <strong>{ev.label}</strong> (+{ev.weight}) — {ev.reason}
                    <span className="fst-italic"> · {attributed(ev.actor)}</span>
                    {ev.actor === me && (
                      <>
                        {' '}
                        <i
                          role="button"
                          aria-label="Edit evidence"
                          title="Edit"
                          className="bi bi-pencil ms-1"
                          style={{ cursor: 'pointer' }}
                          onClick={() => handleEditEvidence(ev)}
                        />
                        <i
                          role="button"
                          aria-label="Delete evidence"
                          title="Delete"
                          className="bi bi-trash ms-1"
                          style={{ cursor: 'pointer' }}
                          onClick={() => handleDeleteEvidence(ev)}
                        />
                      </>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-muted fst-italic mb-1" style={{ fontSize: '0.72rem' }}>
                No analyst evidence added.
              </p>
            )}

          </div>

          {/* Add-evidence popup — shared by Identity and every per-axis panel (#499). Raised above
              the parent panel's z-index so it shows in monitor mode (modal-in-modal). */}
          <Modal
            show={addingEvidence}
            onHide={() => !busy && resetEvidenceForm()}
            centered
            className={zIndex != null ? 'tp-nested-modal' : undefined}
            backdropClassName={zIndex != null ? 'tp-nested-modal-backdrop' : undefined}
          >
            <Modal.Header closeButton={!busy}>
              <Modal.Title style={{ fontSize: '1rem' }}>
                {editingEvidenceId != null ? 'Edit' : 'Add'} evidence · {title}
              </Modal.Title>
            </Modal.Header>
            <Modal.Body>
              <Form.Label className="small mb-1">Supports which label</Form.Label>
              <LabelField
                value={evLabel}
                onChange={setEvLabel}
                options={labelOptions}
                placeholder="e.g. SERVER"
              />
              <Form.Label className="small mb-1">Weight: {evWeight}</Form.Label>
              <input
                type="range"
                min={1}
                max={100}
                value={evWeight}
                onChange={e => setEvWeight(Number(e.target.value))}
                className="form-range mb-3"
              />
              <Form.Label className="small mb-1">Reason (required)</Form.Label>
              <Form.Control
                as="textarea"
                size="sm"
                rows={3}
                className="mb-2"
                placeholder="e.g. confirmed running sshd out-of-band"
                value={evReason}
                onChange={e => setEvReason(e.target.value)}
              />
              <div className="text-muted" style={{ fontSize: '0.72rem' }}>
                Evidence informs the vote and shows in the trail — it does not override the machine.
                Use “I disagree” to set the answer directly.
              </div>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="outline-secondary" size="sm" onClick={resetEvidenceForm} disabled={busy}>
                Cancel
              </Button>
              <Button variant="primary" size="sm" onClick={handleSaveEvidence} disabled={busy || !evLabel.trim() || !evReason.trim()}>
                {busy ? <><Spinner size="sm" className="me-1" />Saving…</> : <><i className="bi bi-check-lg me-1" />{editingEvidenceId != null ? 'Save changes' : 'Add evidence'}</>}
              </Button>
            </Modal.Footer>
          </Modal>
        </>
      )}
    </div>
  );
}
