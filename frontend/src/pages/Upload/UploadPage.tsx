import { useState, useEffect } from 'react';
import { Row, Col } from '@govtechsg/sgds-react';
import { FileUploadZone } from '@components/upload/FileUploadZone';
import { FileList } from '@components/upload/FileList';
import { UploadProgress } from '@components/upload/UploadProgress';
import { useFileUpload } from '@features/upload/hooks/useFileUpload';

const DEFAULT_MAX_BYTES = 512 * 1024 * 1024; // fallback if API is unreachable

export const UploadPage = () => {
  const { uploadFiles, fileStates, isUploading } = useFileUpload();
  const [maxUploadBytes, setMaxUploadBytes] = useState<number>(DEFAULT_MAX_BYTES);

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
                onFileSelect={uploadFiles}
                disabled={isUploading}
                maxSize={maxUploadBytes}
                acceptedFileTypes={acceptedTypes}
              />
            </Col>
          </Row>

          {fileStates.length > 0 && (
            <Row className="justify-content-center mt-3">
              <Col md={8} lg={6}>
                {fileStates.map((fs, i) => (
                  <UploadProgress
                    key={i}
                    fileName={fs.file.name}
                    progress={fs.progress}
                    isUploading={fs.status === 'uploading'}
                    error={fs.error}
                  />
                ))}
              </Col>
            </Row>
          )}

          <FileList />
        </Col>
      </Row>
    </div>
  );
};
