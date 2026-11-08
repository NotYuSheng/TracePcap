import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Button, Card, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';

/** Mirrors FileMetadataDto (the fields this tab shows). */
interface FileVersion {
  fileId: string;
  fileName: string;
  fileSize?: number;
  /** The file API sends LocalDateTime as an array; parseDateTime reads either form. */
  uploadedAt?: string | number[];
  status: string;
  packetCount?: number | null;
  enableNdpi: boolean;
  enableSuricata: boolean;
  enableFileExtraction: boolean;
  derivedFrom?: string | null;
  version: boolean;
}

const OPTIONS: {
  key: 'enableNdpi' | 'enableSuricata' | 'enableFileExtraction';
  label: string;
  help: string;
}[] = [
  {
    key: 'enableNdpi',
    label: 'Application detection (nDPI)',
    help: 'Names the apps in each conversation and flags risks.',
  },
  {
    key: 'enableSuricata',
    label: 'IDS alerts (Suricata)',
    help: 'Matches the Emerging Threats ruleset; the slowest step.',
  },
  {
    key: 'enableFileExtraction',
    label: 'File extraction',
    help: 'Carves files transferred in the traffic.',
  },
];

function apiMessage(err: unknown): string | null {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? null;
}

/**
 * The capture itself (#915 phase 3): how it was analysed, its versions, and re-analysing it with
 * other options, which makes a new version and keeps this one.
 */
export function FileTabPage() {
  const { fileId } = useParams<{ fileId: string }>();
  const navigate = useNavigate();
  const [versions, setVersions] = useState<FileVersion[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [show, setShow] = useState(false);
  const [opts, setOpts] = useState({
    enableNdpi: true,
    enableSuricata: true,
    enableFileExtraction: true,
  });
  const [busy, setBusy] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (!fileId) return;
    apiClient
      .get<FileVersion[]>(API_ENDPOINTS.FILE_VERSIONS(fileId))
      .then(r => setVersions(r.data))
      .catch(() => setError("Couldn't load this capture's details."));
  }, [fileId]);

  if (error) return <Alert variant="danger">{error}</Alert>;
  if (!versions) {
    return (
      <div className="text-muted small py-3">
        <Spinner animation="border" size="sm" className="me-2" />
        Loading…
      </div>
    );
  }
  const current = versions.find(v => v.fileId === fileId);
  if (!current) return <Alert variant="danger">Couldn't find this capture.</Alert>;
  const original = versions.find(v => !v.version);

  const openModal = () => {
    setOpts({
      enableNdpi: current.enableNdpi,
      enableSuricata: current.enableSuricata,
      enableFileExtraction: current.enableFileExtraction,
    });
    setSubmitError(null);
    setShow(true);
  };

  const reanalyse = async () => {
    setBusy(true);
    setSubmitError(null);
    try {
      const r = await apiClient.post<{ fileId: string }>(
        API_ENDPOINTS.FILE_REANALYSES(current.fileId),
        opts
      );
      setShow(false);
      navigate(`/analysis/${r.data.fileId}`);
    } catch (e) {
      setSubmitError(apiMessage(e) ?? "Couldn't start the re-analysis.");
    } finally {
      setBusy(false);
    }
  };

  const unchanged = OPTIONS.every(o => opts[o.key] === current[o.key]);

  return (
    <div data-testid="file-tab">
      {current.version && (
        <Alert variant="info" className="py-2 small">
          This is a re-analysis
          {original ? (
            <>
              {' '}
              of{' '}
              <a
                href={`/analysis/${original.fileId}`}
                onClick={e => {
                  e.preventDefault();
                  navigate(`/analysis/${original.fileId}`);
                }}
              >
                the original upload
              </a>
            </>
          ) : (
            <> (its original upload has since been deleted)</>
          )}
          , with different analysis options.
        </Alert>
      )}

      <Card className="mb-4">
        <Card.Body>
          <div className="d-flex align-items-start mb-2">
            <h5 className="mb-0 me-auto">How this capture was analysed</h5>
            <Button
              size="sm"
              variant="primary"
              onClick={openModal}
              disabled={current.status !== 'completed' && current.status !== 'failed'}
            >
              <i className="bi bi-arrow-repeat me-1" aria-hidden="true" />
              Re-analyse with other options
            </Button>
          </div>
          <ul className="list-unstyled mb-0 small">
            {OPTIONS.map(o => (
              <li key={o.key} className="py-1">
                <i
                  className={`bi ${current[o.key] ? 'bi-check-circle-fill text-success' : 'bi-dash-circle text-muted'} me-2`}
                  aria-hidden="true"
                />
                {o.label}: <strong>{current[o.key] ? 'on' : 'off'}</strong>
              </li>
            ))}
          </ul>
          <p className="small text-muted mt-2 mb-0">
            {current.fileName}
            {current.packetCount != null && <> · {current.packetCount.toLocaleString()} packets</>}
            {current.uploadedAt && <> · analysed {new Date(parseDateTime(current.uploadedAt)).toLocaleString()}</>}
          </p>
        </Card.Body>
      </Card>

      {versions.length > 1 && (
        <Card>
          <Card.Body>
            <h5 className="mb-2">Versions</h5>
            <table className="table table-sm small align-middle mb-0">
              <thead>
                <tr>
                  <th scope="col">Analysed</th>
                  <th scope="col">Options</th>
                  <th scope="col">Status</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {versions.map(v => (
                  <tr key={v.fileId} className={v.fileId === fileId ? 'table-active' : undefined}>
                    <td>
                      {v.uploadedAt ? new Date(parseDateTime(v.uploadedAt)).toLocaleString() : '—'}
                      <div className="text-muted">
                        {v.version ? 'Re-analysis' : 'Original upload'}
                      </div>
                    </td>
                    <td>
                      {OPTIONS.filter(o => v[o.key])
                        .map(o => o.label.split(' (')[0])
                        .join(', ') || 'none'}
                    </td>
                    <td>{v.status}</td>
                    <td className="text-end">
                      {v.fileId === fileId ? (
                        <span className="text-muted">viewing</span>
                      ) : (
                        <Button
                          size="sm"
                          variant="outline-primary"
                          onClick={() => navigate(`/analysis/${v.fileId}`)}
                        >
                          Open
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card.Body>
        </Card>
      )}

      <Modal show={show} onHide={() => !busy && setShow(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Re-analyse with other options</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="small text-muted">
            This makes a new version of the capture, analysed with these options. This analysis is
            kept, along with its labels and notes; the capture's own detection rules are copied to
            the new version.
          </p>
          {submitError && (
            <Alert variant="danger" className="py-2 small">
              {submitError}
            </Alert>
          )}
          {OPTIONS.map(o => (
            <Form.Check
              key={o.key}
              type="switch"
              id={`reanalyse-${o.key}`}
              className="mb-2"
              label={
                <>
                  {o.label}
                  <div className="small text-muted">{o.help}</div>
                </>
              }
              checked={opts[o.key]}
              onChange={e => setOpts(p => ({ ...p, [o.key]: e.target.checked }))}
              disabled={busy}
            />
          ))}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShow(false)} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={reanalyse} disabled={busy}>
            {busy ? (
              <Spinner animation="border" size="sm" />
            ) : unchanged ? (
              'Re-analyse with the same options'
            ) : (
              'Re-analyse'
            )}
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}
