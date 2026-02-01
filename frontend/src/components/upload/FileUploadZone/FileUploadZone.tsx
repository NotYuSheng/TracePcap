import { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import './FileUploadZone.css'

interface FileUploadZoneProps {
  onFileSelect: (file: File) => void
  disabled?: boolean
  maxSize?: number
  acceptedFileTypes?: string[]
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
        onFileSelect(acceptedFiles[0])
      }
    },
    [onFileSelect]
  )

  const { getRootProps, getInputProps, isDragActive, isDragReject, fileRejections } =
    useDropzone({
      onDrop,
      accept: {
        'application/vnd.tcpdump.pcap': acceptedFileTypes,
      },
      maxSize,
      multiple: false,
      disabled,
    })

  return (
    <div className="file-upload-zone-container">
      <div
        {...getRootProps()}
        className={`file-upload-zone ${isDragActive ? 'drag-active' : ''} ${
          isDragReject ? 'drag-reject' : ''
        } ${disabled ? 'disabled' : ''}`}
      >
        <input {...getInputProps()} />

        <div className="upload-icon">
          <i className="bi bi-cloud-upload" style={{ fontSize: '3rem' }}></i>
        </div>

        {isDragActive && !isDragReject && (
          <p className="upload-text">Drop your PCAP file here...</p>
        )}

        {isDragReject && (
          <p className="upload-text error">
            Invalid file type. Please upload a PCAP file.
          </p>
        )}

        {!isDragActive && (
          <>
            <p className="upload-text">
              Drag & drop a PCAP file here, or click to browse
            </p>
            <button type="button" className="btn btn-primary" disabled={disabled}>
              Browse Files
            </button>
            <p className="upload-hint">
              Supported formats: {acceptedFileTypes.join(', ')} (Max {maxSize / 1024 / 1024}MB)
            </p>
          </>
        )}
      </div>

      {fileRejections.length > 0 && (
        <div className="file-rejections">
          {fileRejections.map(({ file, errors }) => (
            <div key={file.name} className="alert alert-danger">
              <strong>{file.name}</strong>
              <ul>
                {errors.map((e) => (
                  <li key={e.code}>{e.message}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
