import { useState, type ReactNode } from 'react';
import { useDropzone } from 'react-dropzone';
import { Link } from 'react-router-dom';
import type { UploadEntry } from '@features/upload/hooks/useFileUpload';
import { UploadQueue, type Rejected } from './UploadQueue';
import type { AnalysisOptions } from '@features/upload/services/uploadService';

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
  /** The files on their way, shown as rows in the panel. */
  uploads: UploadEntry[];
  onClearUploads: () => void;
  /** The panel's own heading, inside the drop target. */
  heading?: ReactNode;
  className?: string;
  labelledBy?: string;
  label?: string;
}

/** Retention in words: "12 hours", "2 days". */
export function retentionText(hours: number): string {
  if (hours % 24 === 0) return `${hours / 24} day${hours === 24 ? '' : 's'}`;
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

/** What the analysis will run with, in a few words: "nDPI and file extraction". */
export function stagesText(o: AnalysisOptions): string {
  const on = [o.enableNdpi && 'nDPI', o.enableSuricata && 'Suricata', o.enableFileExtraction && 'file extraction'].filter(
    (x): x is string => !!x,
  );
  if (on.length === 0) return 'the basic analysis only';
  return on.length === 1 ? on[0] : `${on.slice(0, -1).join(', ')} and ${on[on.length - 1]}`;
}

/**
 * Start here: drop or choose captures, with the stages to run in view beforehand. The whole panel
 * is the drop target, and each file then shows as a row in it until it is ready to open.
 */
export function StartPanel({
  onFiles,
  options,
  onOptionsChange,
  maxBytes,
  maxPackets,
  retentionHours,
  acceptedTypes,
  uploads,
  onClearUploads,
  heading,
  className,
  labelledBy,
  label,
}: Props) {
  const [dragCount, setDragCount] = useState(0);
  const [rejected, setRejected] = useState<Rejected[]>([]);
  const mb = Math.round(maxBytes / 1024 / 1024);
  const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
    onDragEnter: e => setDragCount(e.dataTransfer?.items?.length ?? 0),
    onDrop: (files, rejections) => {
      setRejected(
        rejections.map(({ file, errors }) => ({
          name: file.name,
          reason: errors.some(e => e.code === 'file-too-large')
            ? `Too big: the limit is ${mb} MB. Split it with editcap -c and upload the parts.`
            : errors.some(e => e.code === 'file-invalid-type')
              ? `Not a capture. Only ${acceptedTypes.join(', ')} files can be analysed.`
              : errors.map(e => e.message).join('; '),
        })),
      );
      if (files.length > 0) onFiles(files);
    },
    accept: { 'application/vnd.tcpdump.pcap': acceptedTypes },
    maxSize: maxBytes,
    multiple: true,
    noClick: true,
    noKeyboard: true,
  });

  return (
    <section
      {...getRootProps({ className: `${className ?? ''} home-drop-target${isDragActive ? ' drag-active' : ''}` })}
      aria-labelledby={labelledBy}
      aria-label={label}
      data-testid="home-drop"
    >
      <input {...getInputProps()} />
      {heading}
      {isDragActive && (
        <div className="home-drop-overlay" aria-hidden="true">
          <b>
            Drop to analyse {dragCount > 1 ? `${dragCount} captures` : 'the capture'}
          </b>
          <span>with {stagesText(options)}</span>
        </div>
      )}
      <div className="home-drop">
        <span className="home-drop-icon" aria-hidden="true">
          <i className="bi bi-upload" />
        </span>
        <div>
          <div className="fw-semibold">Drop captures here</div>
          <div className="home-drop-hint">
            {acceptedTypes.join(', ')} · {mb} MB
            {maxPackets > 0 ? ` and ${maxPackets.toLocaleString()} packets` : ''} each
          </div>
        </div>
      </div>
      <button type="button" className="btn btn-outline-primary home-choose" onClick={open}>
        {uploads.length > 0 ? 'Add more' : 'Choose files'}
      </button>

      <UploadQueue
        uploads={uploads}
        rejected={rejected}
        onClear={() => {
          setRejected([]);
          onClearUploads();
        }}
      />

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
    </section>
  );
}
