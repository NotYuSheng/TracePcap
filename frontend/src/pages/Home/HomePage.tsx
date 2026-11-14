import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileList } from '@components/upload/FileList';
import { useFileUpload } from '@features/upload/hooks/useFileUpload';
import type { AnalysisOptions } from '@features/upload/services/uploadService';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { env } from '@/config/env';
import { StartPanel } from './StartPanel';
import { RecentActivity } from './RecentActivity';
import './HomePage.css';

const DEFAULT_MAX_BYTES = 512 * 1024 * 1024; // fallback if the API is unreachable
// Mirrors the backend app.max-packets default so the hint stays honest when /system/limits is
// unreachable; the server enforces it either way.
const DEFAULT_MAX_PACKETS = 2_000_000;

const STEPS = [
  { title: 'Upload', what: 'A capture from Wireshark, tcpdump or a network tap.' },
  { title: 'TracePcap analyses it', what: 'Protocols, devices, intrusion alerts and files.' },
  { title: 'Explore', what: 'The network map, conversations, a written story, packet replay.' },
];

/**
 * The home page: start an analysis on the left; what happened lately and every capture on the
 * right. With no captures yet it is a first-run page that explains what TracePcap does.
 */
export const HomePage = () => {
  const navigate = useNavigate();
  const { uploadFiles, uploads, clearFinished, isUploading } = useFileUpload();
  const [maxBytes, setMaxBytes] = useState(DEFAULT_MAX_BYTES);
  const [maxPackets, setMaxPackets] = useState(DEFAULT_MAX_PACKETS);
  const [retentionHours, setRetentionHours] = useState<number | null>(null);
  const [hasFiles, setHasFiles] = useState<boolean | null>(null);
  const [options, setOptions] = useState<AnalysisOptions>({
    enableNdpi: true,
    // Suricata is opt-in: it is the slowest stage, so it starts off and the box says what it costs.
    enableSuricata: false,
    enableFileExtraction: true,
  });

  useEffect(() => {
    apiClient
      .get<{ maxUploadBytes?: number; maxUploadPackets?: number; fileRetentionHours?: number }>(
        API_ENDPOINTS.SYSTEM_LIMITS
      )
      .then(({ data }) => {
        if (data.maxUploadBytes) setMaxBytes(data.maxUploadBytes);
        if (typeof data.maxUploadPackets === 'number') setMaxPackets(data.maxUploadPackets);
        if (typeof data.fileRetentionHours === 'number') setRetentionHours(data.fileRetentionHours);
      })
      .catch(() => {
        // Defaults stand; the server enforces the real limits.
      });
    apiClient
      .get<{ total?: number }>(API_ENDPOINTS.FILES_LIST, { params: { page: 1, pageSize: 1 } })
      .then(({ data }) => setHasFiles((data.total ?? 0) > 0))
      .catch(() => setHasFiles(true));
  }, []);

  // One file: open it as soon as it is uploaded (not a duplicate, so its warning is seen).
  useEffect(() => {
    if (uploads.length !== 1 || isUploading) return;
    const u = uploads[0];
    if (u.fileId && !u.error && !u.isDuplicate) navigate(`/analysis/${u.fileId}`);
  }, [uploads, isUploading, navigate]);

  const panel = {
    onFiles: (files: File[]) => uploadFiles(files, options),
    options,
    onOptionsChange: setOptions,
    maxBytes,
    maxPackets,
    retentionHours,
    acceptedTypes: env.SUPPORTED_FILE_TYPES,
    uploads,
    onClearUploads: clearFinished,
  };

  if (hasFiles === false) {
    return (
      <div className="home-first-run">
        <div className="home-hero">
          <h1>Turn a packet capture into a picture of the network</h1>
          <p>
            Drop a capture and TracePcap works out which devices are there, what each one is, who
            talked to whom, and what looks wrong. Everything runs on this machine: nothing is sent
            anywhere.
          </p>
        </div>
        <StartPanel {...panel} className="home-card home-start home-start-wide" label="Analyse a capture" />
        <ol className="home-steps">
          {STEPS.map((s, i) => (
            <li key={s.title}>
              <span className="home-step-n" aria-hidden="true">
                {i + 1}
              </span>
              <span>
                <span className="fw-semibold">{s.title}</span>
                <br />
                <span className="text-muted">{s.what}</span>
              </span>
            </li>
          ))}
        </ol>
      </div>
    );
  }

  return (
    <div className="home-page">
      <StartPanel
        {...panel}
        className="home-card home-start"
        labelledBy="home-start-title"
        heading={
          <div>
            <h1 id="home-start-title" className="home-start-title">
              Analyse a capture
            </h1>
            <p className="home-start-lede">
              See who talked to whom, what each device is, and what looks wrong.
            </p>
          </div>
        }
      />
      <div className="home-side">
        <RecentActivity retentionHours={retentionHours} />
        <FileList defaultPageSize={5} />
      </div>
    </div>
  );
};
