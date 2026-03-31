import { useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Card } from '@govtechsg/sgds-react';
import { CloudUpload } from 'lucide-react';
import { formatBytes } from '@/utils/formatters';
import './FileUploadZone.css';

interface FileUploadZoneProps {
  onFileSelect: (files: File[]) => void;
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
        onFileSelect(acceptedFiles);
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
    multiple: true,
    disabled,
  });

  return (
    <Card className="upload-card">
      <Card.Body className="text-center p-5">
        <div className="upload-icon my-3">
          <CloudUpload size={64} strokeWidth={1.5} className="text-primary" />
        </div>
        <h4 className="mb-3">Upload PCAP Files</h4>

        <div
          {...getRootProps()}
          className={`upload-dropzone mb-3 ${isDragActive ? 'drag-active' : ''} ${
            isDragReject ? 'drag-reject' : ''
          } ${disabled ? 'disabled' : ''}`}
        >
          <input {...getInputProps()} />

          {isDragActive && !isDragReject ? (
            <p className="mb-0 fw-semibold text-primary">Drop your files here</p>
          ) : isDragReject ? (
            <p className="mb-0 fw-semibold text-danger">Invalid file type</p>
          ) : (
            <>
              <p className="mb-1">
                <strong>Click to browse</strong> or drag &amp; drop
              </p>
              <small className="text-muted">
                {acceptedFileTypes.join(', ')} &middot; up to {Math.round(maxSize / 1024 / 1024)} MB each &middot; multiple files
              </small>
            </>
          )}
        </div>

        {fileRejections.length > 0 && (
          <div className="mt-3">
            {fileRejections.map(({ file, errors }) => (
              <div key={file.name} className="alert alert-danger text-start">
                <strong>{file.name}</strong>
                <ul className="mb-0 mt-2">
                  {errors.map(e => (
                    <li key={e.code}>
                      {e.code === 'file-invalid-type'
                        ? `Unsupported file type. Only ${acceptedFileTypes.join(', ')} files are accepted.`
                        : e.code === 'file-too-large'
                          ? `File is larger than ${formatBytes(maxSize)}.`
                          : e.message}
                    </li>
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
