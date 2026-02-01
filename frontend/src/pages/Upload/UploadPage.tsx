import { Row, Col } from '@govtechsg/sgds-react'
import { FileUploadZone } from '@components/upload/FileUploadZone'
import { FileList } from '@components/upload/FileList'
import { useFileUpload } from '@features/upload/hooks/useFileUpload'

export const UploadPage = () => {
  const { uploadFile, isUploading } = useFileUpload()

  const maxSize = parseInt(import.meta.env.VITE_MAX_UPLOAD_SIZE || '100000000')
  const acceptedTypes = (import.meta.env.VITE_SUPPORTED_FILE_TYPES || '.pcap,.pcapng,.cap').split(',')

  return (
    <div className="upload-page">
      <Row className="justify-content-center">
        <Col lg={10}>
          <div className="upload-header text-center mb-4">
            <h2 className="mb-2">Upload PCAP File</h2>
            <p className="text-muted">
              Upload your network capture files for detailed analysis and visualization
            </p>
          </div>

          <Row className="justify-content-center">
            <Col md={8} lg={6}>
              <FileUploadZone
                onFileSelect={uploadFile}
                disabled={isUploading}
                maxSize={maxSize}
                acceptedFileTypes={acceptedTypes}
              />
            </Col>
          </Row>

          <FileList />
        </Col>
      </Row>
    </div>
  )
}
