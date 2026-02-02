import { useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Card } from '@govtechsg/sgds-react';
import { CloudUpload } from 'lucide-react';
import './FileUploadZone.css';

interface FileUploadZoneProps {
  onFileSelect: (file: File) => void;
  disabled?: boolean;
  maxSize?: number;
  acceptedFileTypes?: string[];
}

export const FileUploadZone = ({
  onFileSelect,
  disabled = false,
  maxSize = 500 * 1024 * 1024, // 500MB default
  acceptedFileTypes = ['.pcap', '.pcapng', '.cap'],
}: FileUploadZoneProps) => {
  const onDrop = useCallback(
    (acceptedFiles: File[]) => {
      if (acceptedFiles.length > 0) {
        onFileSelect(acceptedFiles[0]);
      }
    },
    [onFileSelect]
  );

  const { getRootProps, getInputProps, isDragActive, isDragReject, fileRejections } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': acceptedFileTypes,
    },
    maxSize,
    multiple: false,
    disabled,
  });

  return (
    <Card className="upload-card">
      <Card.Body className="text-center p-5">
        <div className="upload-icon my-3">
          <CloudUpload size={64} strokeWidth={1.5} className="text-primary" />
        </div>
        <h4 className="mb-3">Upload PCAP File</h4>

        <div
          {...getRootProps()}
          className={`upload-dropzone mb-3 ${isDragActive ? 'drag-active' : ''} ${
            isDragReject ? 'drag-reject' : ''
          } ${disabled ? 'disabled' : ''}`}
        >
          <input {...getInputProps()} />

          {isDragActive && !isDragReject ? (
            <p className="mb-2">
              <strong>Drop your file here</strong>
            </p>
          ) : isDragReject ? (
            <p className="mb-2 text-danger">
              <strong>Invalid file type</strong>
            </p>
          ) : (
            <>
              <p className="mb-2">
                <strong>Click to browse</strong> or drag & drop
              </p>
              <small className="text-muted">
                Supports {acceptedFileTypes.join(', ')} (max {Math.round(maxSize / 1024 / 1024)}MB)
              </small>
            </>
          )}
        </div>

        {disabled && (
          <div className="text-center">
            <span
              className="spinner-border spinner-border-sm me-2"
              role="status"
              aria-hidden="true"
            ></span>
            <span>Uploading...</span>
          </div>
        )}

        {fileRejections.length > 0 && (
          <div className="mt-3">
            {fileRejections.map(({ file, errors }) => (
              <div key={file.name} className="alert alert-danger text-start">
                <strong>{file.name}</strong>
                <ul className="mb-0 mt-2">
                  {errors.map(e => (
                    <li key={e.code}>{e.message}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </Card.Body>
    </Card>
  );
};
