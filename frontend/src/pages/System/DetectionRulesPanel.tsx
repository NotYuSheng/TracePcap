import { useEffect, useMemo, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Pagination } from '@components/common/Pagination/Pagination';
import { Spinner } from '@components/common/Spinner/Spinner';
import { usePermission } from '@/features/me/useMe';
import {
  detectionRulesService,
  errorMessage,
  fieldErrors,
  toInput,
  type DetectionRule,
  type RuleImportResult,
} from '@/features/detectionRules/detectionRulesService';
import { describeCriteria } from '@/features/detectionRules/describeCriteria';
import { RuleSyncBanner } from '@/features/detectionRules/RuleSyncBanner';
import { RuleEditorModal } from './RuleEditorModal';

const PAGE_SIZE = 25;

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'bg-danger',
  high: 'bg-warning text-dark',
  medium: 'bg-info text-dark',
  low: 'bg-secondary',
};

/**
 * Global detection rules (#925 phase 1), in the System console. Everyone can see them; editing
 * needs the "Edit global detection rules" permission, and every change is in the audit log.
 */
export function DetectionRulesPanel() {
  const { allowed, reason } = usePermission('DETECTION_RULES_GLOBAL');
  const [rules, setRules] = useState<DetectionRule[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [reload, setReload] = useState(0);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<DetectionRule | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [deleting, setDeleting] = useState<DetectionRule | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    detectionRulesService
      .list()
      .then(r => {
        setRules(r);
        setLoadError(false);
      })
      .catch(() => setLoadError(true));
  }, [reload]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!rules) return [];
    if (!q) return rules;
    return rules.filter(
      r =>
        r.name.toLowerCase().includes(q) ||
        (r.description ?? '').toLowerCase().includes(q) ||
        describeCriteria(r).toLowerCase().includes(q)
    );
  }, [rules, search]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const shown = filtered.slice(
    (Math.min(page, totalPages) - 1) * PAGE_SIZE,
    Math.min(page, totalPages) * PAGE_SIZE
  );

  const refresh = () => setReload(n => n + 1);

  const toggle = async (r: DetectionRule) => {
    setBusy(true);
    setError(null);
    try {
      await detectionRulesService.update(r.id, { ...toInput(r), enabled: !r.enabled });
      refresh();
    } catch (e) {
      setError(errorMessage(e, "Couldn't change the rule."));
    } finally {
      setBusy(false);
    }
  };

  const doExport = async () => {
    setError(null);
    try {
      const blob = await detectionRulesService.exportYaml();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'tracepcap-detection-rules.yml';
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(errorMessage(e, "Couldn't export the rules."));
    }
  };

  if (loadError) return <p className="text-danger small">Couldn't load the detection rules.</p>;
  if (!rules) {
    return (
      <div className="text-muted small py-3">
        <Spinner animation="border" size="sm" className="me-2" />
        Loading…
      </div>
    );
  }

  return (
    <div>
      <p className="small text-muted">
        Global rules flag matching conversations in every capture analysed from now on, alongside
        nDPI's built-in risk flags. Every change is recorded in the audit log.
      </p>
      {!allowed && (
        <Alert variant="info" className="py-2" data-testid="rules-locked">
          <i className="bi bi-lock me-2" aria-hidden="true" />
          You can view these rules but not change them: {reason ?? 'only admins can change them.'}
        </Alert>
      )}
      {error && (
        <Alert variant="danger" className="py-2">
          {error}
        </Alert>
      )}
      <RuleSyncBanner
        canReapply={allowed}
        reason={reason}
        refreshKey={reload}
        onReapplied={refresh}
      />
      {notice && (
        <Alert variant="success" className="py-2" onClose={() => setNotice(null)} dismissible>
          {notice}
        </Alert>
      )}
      <div className="d-flex flex-wrap gap-2 mb-3">
        <Form.Control
          type="search"
          size="sm"
          style={{ maxWidth: 320 }}
          placeholder="Search rules…"
          aria-label="Search detection rules"
          value={search}
          onChange={e => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
        <div className="ms-auto d-flex gap-2">
          <Button size="sm" variant="outline-secondary" onClick={doExport}>
            <i className="bi bi-download me-1" aria-hidden="true" />
            Export
          </Button>
          <Button
            size="sm"
            variant="outline-secondary"
            onClick={() => setShowImport(true)}
            disabled={!allowed}
          >
            <i className="bi bi-upload me-1" aria-hidden="true" />
            Import
          </Button>
          <Button
            size="sm"
            variant="primary"
            onClick={() => {
              setEditing(null);
              setShowEditor(true);
            }}
            disabled={!allowed}
          >
            <i className="bi bi-plus me-1" aria-hidden="true" />
            Add rule
          </Button>
        </div>
      </div>

      {rules.length === 0 && <p className="small text-muted">No detection rules yet.</p>}
      {rules.length > 0 && filtered.length === 0 && (
        <p className="small text-muted">No rules match "{search}".</p>
      )}
      {shown.length > 0 && (
        <div className="table-responsive">
          <table className="table table-sm small align-middle">
            <thead>
              <tr>
                <th scope="col">On</th>
                <th scope="col">Rule</th>
                <th scope="col">Matches</th>
                <th scope="col">Last changed</th>
                <th scope="col" className="text-end">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.map(r => (
                <tr key={r.id} className={r.enabled ? undefined : 'text-muted'}>
                  <td>
                    <Form.Check
                      type="switch"
                      id={`rule-on-${r.id}`}
                      aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`}
                      checked={r.enabled}
                      onChange={() => toggle(r)}
                      disabled={!allowed || busy}
                    />
                  </td>
                  <td>
                    <div className="fw-semibold font-monospace">{r.name}</div>
                    <span className={`badge ${SEVERITY_CLASS[r.severity] ?? 'bg-secondary'}`}>
                      {r.severity}
                    </span>
                    {r.description && <div className="text-muted">{r.description}</div>}
                  </td>
                  <td className="font-monospace">{describeCriteria(r)}</td>
                  <td className="text-nowrap">
                    {r.updatedBy}
                    <div className="text-muted">
                      {new Date(r.updatedAt).toLocaleString()} · v{r.version}
                    </div>
                  </td>
                  <td className="text-end text-nowrap">
                    <Button
                      size="sm"
                      variant="outline-primary"
                      className="me-1"
                      aria-label={`${allowed ? 'Edit' : 'View'} ${r.name}`}
                      onClick={() => {
                        setEditing(r);
                        setShowEditor(true);
                      }}
                    >
                      <i className={`bi ${allowed ? 'bi-pencil' : 'bi-eye'}`} aria-hidden="true" />
                    </Button>
                    <Button
                      size="sm"
                      variant="outline-danger"
                      aria-label={`Delete ${r.name}`}
                      onClick={() => setDeleting(r)}
                      disabled={!allowed}
                    >
                      <i className="bi bi-trash" aria-hidden="true" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {filtered.length > PAGE_SIZE && (
        <Pagination
          currentPage={Math.min(page, totalPages)}
          totalPages={totalPages}
          totalItems={filtered.length}
          pageSize={PAGE_SIZE}
          onPageChange={setPage}
          showPageSizeSelector={false}
        />
      )}

      <RuleEditorModal
        show={showEditor}
        rule={editing}
        readOnly={!allowed}
        onHide={() => setShowEditor(false)}
        onSaved={refresh}
      />

      <Modal show={deleting !== null} onHide={() => !busy && setDeleting(null)}>
        <Modal.Header closeButton>
          <Modal.Title>Delete rule</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          Delete <strong className="font-monospace">{deleting?.name}</strong>? It stops flagging new
          analyses. To pause it instead, switch it off. The deletion is recorded in the audit log.
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setDeleting(null)} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={busy}
            onClick={async () => {
              if (!deleting) return;
              setBusy(true);
              setError(null);
              try {
                await detectionRulesService.remove(deleting.id);
                setDeleting(null);
                refresh();
              } catch (e) {
                setError(errorMessage(e, "Couldn't delete the rule."));
                setDeleting(null);
              } finally {
                setBusy(false);
              }
            }}
          >
            Delete
          </Button>
        </Modal.Footer>
      </Modal>

      <ImportRulesModal
        show={showImport}
        onHide={() => setShowImport(false)}
        onImported={result => {
          refresh();
          setNotice(
            `Imported: ${result.created} new, ${result.updated} updated, ${result.unchanged} unchanged` +
              (result.deleted ? `, ${result.deleted} deleted` : '') +
              (result.duplicates.length
                ? `. Repeated in the file, first one used: ${result.duplicates.join(', ')}`
                : '') +
              '.'
          );
        }}
      />
    </div>
  );
}

/** Upload a rules file (an export, or an old signatures.yml). All or nothing. */
function ImportRulesModal({
  show,
  onHide,
  onImported,
}: {
  show: boolean;
  onHide: () => void;
  onImported: (r: RuleImportResult) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<'MERGE' | 'REPLACE'>('MERGE');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [problems, setProblems] = useState<[string, string][]>([]);

  useEffect(() => {
    if (show) {
      setFile(null);
      setMode('MERGE');
      setError(null);
      setProblems([]);
    }
  }, [show]);

  const run = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    setProblems([]);
    try {
      const result = await detectionRulesService.importYaml(await file.text(), mode);
      onImported(result);
      onHide();
    } catch (e) {
      setError(errorMessage(e, "Couldn't import the file."));
      setProblems(Object.entries(fieldErrors(e) ?? {}));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal show={show} onHide={() => !busy && onHide()}>
      <Modal.Header closeButton>
        <Modal.Title>Import rules</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="small text-muted">
          A file exported from TracePcap, or an old{' '}
          <span className="font-monospace">signatures.yml</span>. Rules are matched to existing ones
          by name. If any rule in the file is invalid, nothing is imported.
        </p>
        {error && (
          <Alert variant="danger" className="py-2 small">
            {error}
            {problems.length > 0 && (
              <ul className="mb-0 mt-1" data-testid="import-problems">
                {problems.map(([k, v]) => (
                  <li key={k}>
                    <span className="font-monospace">{k}</span>: {v}
                  </li>
                ))}
              </ul>
            )}
          </Alert>
        )}
        <Form.Group className="mb-3">
          <Form.Label htmlFor="rules-file">Rules file</Form.Label>
          <Form.Control
            id="rules-file"
            type="file"
            accept=".yml,.yaml,text/yaml,application/yaml"
            onChange={e => setFile((e.target as HTMLInputElement).files?.[0] ?? null)}
            disabled={busy}
          />
        </Form.Group>
        <Form.Check
          type="radio"
          id="import-merge"
          name="import-mode"
          label="Add and update rules; keep the others"
          checked={mode === 'MERGE'}
          onChange={() => setMode('MERGE')}
          disabled={busy}
        />
        <Form.Check
          type="radio"
          id="import-replace"
          name="import-mode"
          label="Replace: also delete rules that aren't in the file"
          checked={mode === 'REPLACE'}
          onChange={() => setMode('REPLACE')}
          disabled={busy}
        />
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide} disabled={busy}>
          Cancel
        </Button>
        <Button variant="primary" onClick={run} disabled={busy || !file}>
          {busy ? <Spinner animation="border" size="sm" /> : 'Import'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
