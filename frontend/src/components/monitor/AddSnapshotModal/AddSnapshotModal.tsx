import { Spinner } from '@components/common/Spinner/Spinner';
import { useEffect, useRef, useState } from 'react';
import { Alert, Badge, Button, Modal } from '@govtechsg/sgds-react';
import { useDropzone } from 'react-dropzone';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { uploadService } from '@/features/upload/services/uploadService';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { SubnetOverrideInput } from '@/features/monitor/types/monitor.types';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';

interface AddSnapshotModalProps {
  show: boolean;
  onHide: () => void;
  existingFileIds: string[];
  onAdd: (fileId: string, subnetOverrides?: SubnetOverrideInput[]) => Promise<void>;
}

async function pollUntilComplete(fileId: string, signal: AbortSignal): Promise<void> {
  while (!signal.aborted) {
    const res = await apiClient.get(API_ENDPOINTS.FILE_METADATA(fileId));
    const status: string = (res.data?.status ?? '').toUpperCase();
    if (status === 'COMPLETED') return;
    if (status === 'ERROR' || status === 'FAILED') throw new Error('Analysis failed');
    await new Promise(r => setTimeout(r, 2000));
  }
}

function globalToInput(s: SubnetDefinition): SubnetOverrideInput {
  return { cidr: s.cidr, label: s.label ?? null, description: s.description ?? null, inherited: true };
}

export const AddSnapshotModal = ({
  show,
  onHide,
  onAdd,
}: AddSnapshotModalProps) => {
  const [uploadFiles, setUploadFiles] = useState<File[]>([]);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadPhase, setUploadPhase] = useState<'idle' | 'uploading' | 'analyzing' | 'adding' | 'done' | 'error'>('idle');
  const [uploadCurrent, setUploadCurrent] = useState(0);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Subnet override state
  const [showSubnets, setShowSubnets] = useState(false);
  const [subnetOverrides, setSubnetOverrides] = useState<SubnetOverrideInput[]>([]);
  const [subnetOverridesActive, setSubnetOverridesActive] = useState(false);
  const [loadingSubnets, setLoadingSubnets] = useState(false);
  const [newCidr, setNewCidr] = useState('');

  useEffect(() => {
    if (!show) return;
    setUploadFiles([]);
    setUploadProgress(0);
    setUploadPhase('idle');
    setUploadCurrent(0);
    setUploadError(null);
    setShowSubnets(false);
    setSubnetOverrides([]);
    setSubnetOverridesActive(false);
    setNewCidr('');
  }, [show]);

  const handleToggleSubnets = async () => {
    const next = !showSubnets;
    setShowSubnets(next);
    if (next && !subnetOverridesActive) {
      setLoadingSubnets(true);
      try {
        const globals = await subnetService.list();
        setSubnetOverrides(globals.map(globalToInput));
      } catch {
        // fetch failed — user can still add CIDRs manually
      } finally {
        setSubnetOverridesActive(true);
        setLoadingSubnets(false);
      }
    }
  };

  const updateOverride = (index: number, field: 'cidr' | 'label', value: string | null) => {
    setSubnetOverrides(prev => prev.map((o, i) =>
      i === index ? { ...o, [field]: value, inherited: false } : o
    ));
  };

  const removeOverride = (index: number) => {
    setSubnetOverrides(prev => prev.filter((_, i) => i !== index));
  };

  const addOverride = () => {
    const cidr = newCidr.trim();
    if (!cidr) return;
    setSubnetOverrides(prev => [...prev, { cidr, label: null, description: null, inherited: false }]);
    setNewCidr('');
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: { 'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng', '.cap'] },
    multiple: true,
    disabled: uploadPhase !== 'idle',
    onDrop: accepted => { if (accepted.length > 0) setUploadFiles(accepted); },
  });

  const handleUploadAndAdd = async () => {
    if (uploadFiles.length === 0) return;
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setUploadError(null);

    const overridesToSend = subnetOverridesActive ? subnetOverrides : undefined;

    try {
      for (let i = 0; i < uploadFiles.length; i++) {
        const file = uploadFiles[i];
        setUploadCurrent(i + 1);
        setUploadPhase('uploading');
        setUploadProgress(0);

        let fileId: string;
        try {
          const result = await uploadService.uploadPcap(
            file,
            p => setUploadProgress(p),
            { enableNdpi: true, enableFileExtraction: true, source: 'MONITOR' },
          );
          fileId = result.fileId;
        } catch (uploadErr: any) {
          if (uploadErr?.response?.status === 409 && uploadErr.response.data?.existingFileId) {
            fileId = uploadErr.response.data.existingFileId;
          } else {
            throw uploadErr;
          }
        }

        setUploadPhase('analyzing');
        await pollUntilComplete(fileId, ctrl.signal);

        setUploadPhase('adding');
        await onAdd(fileId, overridesToSend);
      }

      setUploadPhase('done');
      setTimeout(onHide, 800);
    } catch (err: any) {
      if (ctrl.signal.aborted) return;
      const msg = err?.response?.data?.message ?? err?.message ?? 'Upload failed.';
      setUploadError(msg);
      setUploadPhase('error');
    }
  };

  const isBusy = uploadPhase === 'uploading' || uploadPhase === 'analyzing' || uploadPhase === 'adding';
  const totalFiles = uploadFiles.length;

  const phaseLabel: Record<typeof uploadPhase, string> = {
    idle: '',
    uploading: `Uploading… ${uploadProgress}%`,
    analyzing: 'Analysing PCAP…',
    adding: 'Adding to network…',
    done: 'Done!',
    error: '',
  };

  return (
    <Modal show={show} onHide={isBusy ? undefined : onHide} size="lg">
      <Modal.Header closeButton={!isBusy}>
        <Modal.Title>Add PCAP Snapshot</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {uploadPhase === 'idle' || uploadPhase === 'error' ? (
          <>
            <div
              {...getRootProps()}
              className={`border rounded p-4 text-center mb-3 ${isDragActive ? 'border-primary bg-primary-subtle' : ''}`}
              style={{ cursor: 'pointer', borderStyle: 'dashed' }}
            >
              <input {...getInputProps()} />
              <i className="bi bi-cloud-upload fs-2 text-primary d-block mb-2"></i>
              {uploadFiles.length > 0 ? (
                uploadFiles.length === 1 ? (
                  <>
                    <div className="fw-semibold">{uploadFiles[0].name}</div>
                    <small className="text-muted">
                      {uploadFiles[0].size >= 1024 * 1024
                        ? `${(uploadFiles[0].size / 1024 / 1024).toFixed(1)} MB`
                        : `${(uploadFiles[0].size / 1024).toFixed(1)} KB`} — click to change
                    </small>
                  </>
                ) : (
                  <>
                    <div className="fw-semibold">{uploadFiles.length} files selected</div>
                    <small className="text-muted">{uploadFiles.map(f => f.name).join(', ')}</small>
                  </>
                )
              ) : isDragActive ? (
                <p className="mb-0 fw-semibold text-primary">Drop here</p>
              ) : (
                <>
                  <p className="mb-1"><strong>Click to browse</strong> or drag &amp; drop</p>
                  <small className="text-muted">.pcap / .pcapng / .cap</small>
                </>
              )}
            </div>

            {/* Subnet Overrides collapsible */}
            <div className="border rounded mb-3">
              <button
                type="button"
                className="btn w-100 text-start d-flex align-items-center justify-content-between px-3 py-2"
                onClick={handleToggleSubnets}
              >
                <span className="d-flex align-items-center gap-2">
                  <i className="bi bi-diagram-2 text-secondary" />
                  <span className="fw-semibold small">Subnet Overrides</span>
                  <span className="text-muted" style={{ fontSize: '0.75rem' }}>optional</span>
                  {subnetOverridesActive && (
                    <Badge bg={subnetOverrides.length > 0 ? 'primary' : 'secondary'} style={{ fontSize: '0.65rem' }}>
                      {subnetOverrides.length > 0 ? `${subnetOverrides.length} ranges` : 'empty — no subnets'}
                    </Badge>
                  )}
                </span>
                <i className={`bi bi-chevron-${showSubnets ? 'up' : 'down'} text-muted`} style={{ fontSize: '0.75rem' }} />
              </button>

              {showSubnets && (
                <div className="px-3 pb-3 border-top">
                  {loadingSubnets ? (
                    <div className="text-center py-3">
                      <Spinner animation="border" size="sm" className="text-primary" />
                      <span className="ms-2 text-muted small">Loading global subnets…</span>
                    </div>
                  ) : (
                    <>
                      <p className="text-muted mb-2 mt-2" style={{ fontSize: '0.8rem' }}>
                        Pre-populated from global subnet definitions.
                        Modify to override internal/external classification for this snapshot only.
                        <strong className="d-block mt-1">Inherited</strong> ranges came from the global config; you can remove or edit them.
                      </p>

                      {subnetOverrides.length > 0 ? (
                        <div className="table-responsive mb-2">
                          <table className="table table-sm table-bordered mb-0" style={{ fontSize: '0.8rem' }}>
                            <thead className="table-light">
                              <tr>
                                <th style={{ width: '38%' }}>CIDR</th>
                                <th>Label</th>
                                <th style={{ width: '5rem' }}></th>
                              </tr>
                            </thead>
                            <tbody>
                              {subnetOverrides.map((o, i) => (
                                <tr key={i}>
                                  <td>
                                    <input
                                      className="form-control form-control-sm font-monospace"
                                      value={o.cidr}
                                      onChange={e => updateOverride(i, 'cidr', e.target.value)}
                                      style={{ fontSize: '0.78rem' }}
                                    />
                                  </td>
                                  <td>
                                    <input
                                      className="form-control form-control-sm"
                                      value={o.label ?? ''}
                                      onChange={e => updateOverride(i, 'label', e.target.value || null)}
                                      placeholder="Optional"
                                      style={{ fontSize: '0.78rem' }}
                                    />
                                  </td>
                                  <td className="text-center align-middle">
                                    {o.inherited && (
                                      <span className="badge bg-secondary me-1" style={{ fontSize: '0.6rem' }}>Inherited</span>
                                    )}
                                    <button
                                      type="button"
                                      className="btn btn-sm btn-outline-danger p-0"
                                      style={{ width: 22, height: 22, lineHeight: 1 }}
                                      onClick={() => removeOverride(i)}
                                      title="Remove"
                                    >
                                      <i className="bi bi-x" style={{ fontSize: '0.75rem' }} />
                                    </button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <p className="text-muted text-center small py-2 mb-2">
                          No ranges configured. If left empty, global subnet definitions will be used.
                        </p>
                      )}

                      <div className="d-flex gap-2 align-items-center">
                        <input
                          className="form-control form-control-sm font-monospace"
                          placeholder="e.g. 192.168.1.0/24"
                          value={newCidr}
                          onChange={e => setNewCidr(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addOverride(); } }}
                          style={{ maxWidth: 200, fontSize: '0.8rem' }}
                        />
                        <Button size="sm" variant="outline-primary" onClick={addOverride} disabled={!newCidr.trim()}>
                          <i className="bi bi-plus me-1" />Add CIDR
                        </Button>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>

            {uploadError && <Alert variant="danger" className="py-2">{uploadError}</Alert>}
            <Button
              variant="primary"
              className="w-100"
              disabled={uploadFiles.length === 0}
              onClick={handleUploadAndAdd}
            >
              <i className="bi bi-upload me-1"></i>
              {uploadFiles.length > 1
                ? `Upload ${uploadFiles.length} files & add to network`
                : 'Upload & add to network'}
            </Button>
          </>
        ) : (
          <div className="text-center py-4">
            {uploadPhase === 'done' ? (
              <div className="text-success fw-semibold fs-5">
                <i className="bi bi-check-circle-fill me-2"></i>Added!
              </div>
            ) : (
              <>
                <Spinner animation="border" className="text-primary mb-3" role="status" />
                <div className="fw-semibold">
                  {totalFiles > 1 && `File ${uploadCurrent} of ${totalFiles} — `}
                  {phaseLabel[uploadPhase]}
                </div>
                {uploadPhase === 'uploading' && (
                  <div className="progress mt-2" style={{ height: 6 }}>
                    <div className="progress-bar" style={{ width: `${uploadProgress}%` }} />
                  </div>
                )}
                {uploadPhase === 'analyzing' && (
                  <small className="text-muted d-block mt-1">
                    This may take a minute for large captures.
                  </small>
                )}
              </>
            )}
          </div>
        )}
      </Modal.Body>
    </Modal>
  );
};
