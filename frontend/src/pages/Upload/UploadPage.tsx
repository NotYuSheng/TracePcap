import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Row, Col, Modal } from '@govtechsg/sgds-react';
import { FileUploadZone } from '@components/upload/FileUploadZone';
import { FileList } from '@components/upload/FileList';
import { UploadProgress } from '@components/upload/UploadProgress';
import { useFileUpload } from '@features/upload/hooks/useFileUpload';
import type { AnalysisOptions } from '@features/upload/services/uploadService';

const DEFAULT_MAX_BYTES = 512 * 1024 * 1024; // fallback if API is unreachable

export const UploadPage = () => {
  const { uploadFiles, uploads, clearUploads, isUploading } = useFileUpload();
  const [maxUploadBytes, setMaxUploadBytes] = useState<number>(DEFAULT_MAX_BYTES);
  const [pendingFiles, setPendingFiles] = useState<File[] | null>(null);
  const [analysisOptions, setAnalysisOptions] = useState<AnalysisOptions>({
    enableNdpi: true,
    enableFileExtraction: true,
  });
  const navigate = useNavigate();

  const acceptedTypes = (import.meta.env.VITE_SUPPORTED_FILE_TYPES || '.pcap,.pcapng,.cap').split(
    ','
  );

  useEffect(() => {
    fetch('/api/system/limits')
      .then(r => r.json())
      .then(data => {
        if (data.maxUploadBytes) setMaxUploadBytes(data.maxUploadBytes);
      })
      .catch(err => {
        console.error('Failed to fetch upload limits, using default.', err);
      });
  }, []);

  // Auto-navigate for single-file uploads only (skip if duplicate so user can see the warning)
  useEffect(() => {
    if (uploads.length !== 1 || isUploading) return;
    const upload = uploads[0];
    if (upload.fileId && !upload.error && !upload.isDuplicate) {
      navigate(`/analysis/${upload.fileId}`);
    }
  }, [uploads, isUploading, navigate]);

  const analysisOptionsEnabled = import.meta.env.VITE_ANALYSIS_OPTIONS !== 'false';

  const handleFileSelect = (files: File[]) => {
    if (!analysisOptionsEnabled) {
      uploadFiles(files, { enableNdpi: true, enableFileExtraction: true });
    } else {
      setPendingFiles(files);
    }
  };

  const handleConfirmUpload = () => {
    if (!pendingFiles) return;
    uploadFiles(pendingFiles, analysisOptions);
    setPendingFiles(null);
  };

  const handleCancelPending = () => {
    setPendingFiles(null);
  };

  return (
    <div className="upload-page">
      <Row className="justify-content-center">
        <Col lg={10}>
          <div className="upload-header text-center mb-4">
            <h2 className="mb-2">Upload PCAP Files</h2>
            <p className="text-muted">
              Upload your network capture files for detailed analysis and visualization
            </p>
          </div>

          <Row className="justify-content-center">
            <Col md={8} lg={6}>
              <FileUploadZone
                onFileSelect={handleFileSelect}
                disabled={isUploading}
                maxSize={maxUploadBytes}
                acceptedFileTypes={acceptedTypes}
              />
            </Col>
          </Row>

          {/* Pre-upload: analysis options confirmation */}
          <Modal show={pendingFiles !== null} onHide={handleCancelPending} centered>
            <Modal.Header closeButton>
              <Modal.Title>
                <i className="bi bi-sliders me-2" />
                Analysis options
              </Modal.Title>
            </Modal.Header>
            <Modal.Body>
              <p className="text-muted mb-3" style={{ fontSize: '0.9rem' }}>
                Select which optional stages to run. Disabling stages reduces analysis time for
                large captures.
              </p>

              <div className="d-flex flex-column gap-3">
                <label className="d-flex align-items-start gap-3" style={{ cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    className="form-check-input mt-1 flex-shrink-0"
                    checked={analysisOptions.enableNdpi}
                    onChange={e =>
                      setAnalysisOptions(o => ({ ...o, enableNdpi: e.target.checked }))
                    }
                  />
                  <div>
                    <div className="fw-semibold">Protocol &amp; application classification</div>
                    <div className="text-muted" style={{ fontSize: '0.82rem' }}>
                      Identifies apps (Zoom, Chrome, etc.), traffic categories, and security risks.
                      Adds ~1–2 min for large captures.
                    </div>
                  </div>
                </label>

                <label className="d-flex align-items-start gap-3" style={{ cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    className="form-check-input mt-1 flex-shrink-0"
                    checked={analysisOptions.enableFileExtraction}
                    onChange={e =>
                      setAnalysisOptions(o => ({ ...o, enableFileExtraction: e.target.checked }))
                    }
                  />
                  <div>
                    <div className="fw-semibold">Embedded file extraction</div>
                    <div className="text-muted" style={{ fontSize: '0.82rem' }}>
                      Extracts files transferred over HTTP and raw TCP/UDP streams. Adds ~1–2 min
                      for large captures.
                    </div>
                  </div>
                </label>
              </div>

              {pendingFiles && pendingFiles.length > 0 && (
                <div className="mt-3 pt-3 border-top text-muted" style={{ fontSize: '0.82rem' }}>
                  <i className="bi bi-file-earmark-binary me-1" />
                  {pendingFiles.length === 1
                    ? pendingFiles[0].name
                    : `${pendingFiles.length} files selected`}
                </div>
              )}
            </Modal.Body>
            <Modal.Footer>
              <button className="btn btn-outline-secondary btn-sm" onClick={handleCancelPending}>
                Cancel
              </button>
              <button className="btn btn-primary btn-sm" onClick={handleConfirmUpload}>
                <i className="bi bi-upload me-1" />
                Start upload
              </button>
            </Modal.Footer>
          </Modal>

          {/* Post-upload: progress / completion */}
          <Modal
            show={uploads.length > 0}
            onHide={() => {
              if (!isUploading) clearUploads();
            }}
            centered
            backdrop={isUploading ? 'static' : true}
            keyboard={!isUploading}
          >
            <Modal.Header closeButton={!isUploading}>
              <Modal.Title>
                {isUploading ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    />
                    Uploading…
                  </>
                ) : (
                  <>
                    <i className="bi bi-check-circle-fill text-success me-2" />
                    Upload complete
                  </>
                )}
              </Modal.Title>
            </Modal.Header>
            <Modal.Body>
              <div className="d-flex flex-column gap-2">
                {uploads.map(u => (
                  <UploadProgress
                    key={u.id}
                    fileName={u.fileName}
                    progress={u.progress}
                    isUploading={u.isUploading}
                    error={u.error}
                    isDuplicate={u.isDuplicate}
                    onAnalyze={u.fileId ? () => navigate(`/analysis/${u.fileId}`) : undefined}
                    onOpenExisting={
                      u.duplicateOfFileId
                        ? () => navigate(`/analysis/${u.duplicateOfFileId}`)
                        : undefined
                    }
                  />
                ))}
              </div>
            </Modal.Body>
          </Modal>

          <FileList />
        </Col>
      </Row>
    </div>
  );
};
