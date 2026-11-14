import { useDropzone } from 'react-dropzone';
import { Link } from 'react-router-dom';
import { Alert } from '@components/common/Alert';
import type { AnalysisOptions } from '@features/upload/services/uploadService';
import { formatBytes } from '@/utils/formatters';

const STAGES: {
  key: 'enableNdpi' | 'enableSuricata' | 'enableFileExtraction';
  name: string;
  what: string;
}[] = [
  {
    key: 'enableNdpi',
    name: 'Protocols and apps (nDPI)',
    what: 'Names the application in each conversation and flags risks.',
  },
  {
    key: 'enableSuricata',
    name: 'Intrusion alerts (Suricata)',
    what: 'Checks traffic against known attack signatures. The slowest step: about 30 to 60 seconds more per capture.',
  },
  {
    key: 'enableFileExtraction',
    name: 'Files in the traffic',
    what: 'Pulls out files sent over HTTP and raw TCP/UDP streams.',
  },
];

interface Props {
  onFiles: (files: File[]) => void;
  options: AnalysisOptions;
  onOptionsChange: (o: AnalysisOptions) => void;
  maxBytes: number;
  maxPackets: number;
  /** Hours a capture is kept; 0 means forever. */
  retentionHours: number | null;
  acceptedTypes: string[];
  disabled?: boolean;
}

/** Retention in words: "12 hours", "2 days". */
export function retentionText(hours: number): string {
  if (hours % 24 === 0) return `${hours / 24} day${hours === 24 ? '' : 's'}`;
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

/**
 * Start here: drop or choose captures, with the analysis stages to run in view beforehand, so
 * nothing about the upload is decided in a popup after the files are picked.
 */
export function StartPanel({
  onFiles,
  options,
  onOptionsChange,
  maxBytes,
  maxPackets,
  retentionHours,
  acceptedTypes,
  disabled,
}: Props) {
  const { getRootProps, getInputProps, isDragActive, isDragReject, fileRejections, open } =
    useDropzone({
      onDrop: files => {
        if (files.length > 0) onFiles(files);
      },
      accept: { 'application/vnd.tcpdump.pcap': acceptedTypes },
      maxSize: maxBytes,
      multiple: true,
      disabled,
      noClick: true,
      noKeyboard: true,
    });

  return (
    <>
      <div
        {...getRootProps()}
        className={`home-drop${isDragActive ? ' drag-active' : ''}${isDragReject ? ' drag-reject' : ''}${disabled ? ' disabled' : ''}`}
        data-testid="home-drop"
      >
        <input {...getInputProps()} />
        <i className="bi bi-upload home-drop-icon" aria-hidden="true" />
        {isDragActive && !isDragReject ? (
          <div className="fw-semibold">Drop to upload</div>
        ) : isDragReject ? (
          <div className="fw-semibold text-danger">That isn’t a capture file</div>
        ) : (
          <div>
            <button
              type="button"
              className="btn btn-link p-0 fw-semibold align-baseline"
              onClick={open}
              disabled={disabled}
            >
              Choose files
            </button>{' '}
            or drop them here
          </div>
        )}
        <div className="home-drop-hint">
          {acceptedTypes.join(', ')} · up to {Math.round(maxBytes / 1024 / 1024)} MB
          {maxPackets > 0 ? ` and ${maxPackets.toLocaleString()} packets` : ''} each
        </div>
      </div>

      {fileRejections.map(({ file, errors }) => (
        <Alert key={file.name} variant="danger" className="small mb-0">
          <strong>{file.name}</strong>:{' '}
          {errors
            .map(e =>
              e.code === 'file-invalid-type'
                ? `only ${acceptedTypes.join(', ')} files can be analysed`
                : e.code === 'file-too-large'
                  ? `larger than ${formatBytes(maxBytes)}`
                  : e.message
            )
            .join('; ')}
        </Alert>
      ))}

      <fieldset className="home-stages">
        <legend>Analyse with</legend>
        {STAGES.map(s => (
          <label key={s.key} className="home-stage">
            <input
              type="checkbox"
              className="form-check-input"
              checked={options[s.key]}
              onChange={e => onOptionsChange({ ...options, [s.key]: e.target.checked })}
            />
            <span>
              <span className="fw-semibold">{s.name}</span>
              <br />
              <span className="text-muted">{s.what}</span>
            </span>
          </label>
        ))}
      </fieldset>

      {retentionHours != null && (
        <p className="home-retention">
          {retentionHours > 0 ? (
            <>
              Captures are kept {retentionText(retentionHours)}. Add one to a{' '}
              <Link to="/monitor">monitored network</Link> to keep it.
            </>
          ) : (
            'Captures are kept until you delete them.'
          )}
        </p>
      )}
    </>
  );
}
