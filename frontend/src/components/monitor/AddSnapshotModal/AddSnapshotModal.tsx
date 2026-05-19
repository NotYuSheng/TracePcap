import { Spinner } from '@components/common/Spinner/Spinner';
import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Modal } from '@govtechsg/sgds-react';
import { useDropzone } from 'react-dropzone';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { uploadService } from '@/features/upload/services/uploadService';

interface AddSnapshotModalProps {
  show: boolean;
  onHide: () => void;
  existingFileIds: string[];
  onAdd: (fileId: string) => Promise<void>;
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

  useEffect(() => {
    if (!show) return;
    setUploadFiles([]);
    setUploadProgress(0);
    setUploadPhase('idle');
    setUploadCurrent(0);
    setUploadError(null);
  }, [show]);

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
        await onAdd(fileId);
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
