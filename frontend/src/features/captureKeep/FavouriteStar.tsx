import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { captureKeepService } from './captureKeepService';
import './captureKeep.css';

/** A capture's favourite star, beside its name on every analysis tab. Personal, per account. */
export function FavouriteStar({ fileId, fileName }: { fileId: string; fileName: string }) {
  const [on, setOn] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    apiClient
      .get<{ favourite?: boolean }>(API_ENDPOINTS.FILE_METADATA(fileId))
      .then(r => alive && setOn(!!r.data.favourite))
      .catch(() => alive && setOn(null));
    return () => {
      alive = false;
    };
  }, [fileId]);

  if (on == null) return null;
  const toggle = async () => {
    setBusy(true);
    setOn(!on);
    try {
      await captureKeepService.setFavourite(fileId, !on);
    } catch {
      setOn(on);
    } finally {
      setBusy(false);
    }
  };
  return (
    <button
      type="button"
      className={`captures-star${on ? ' on' : ''}`}
      aria-pressed={on}
      aria-label={`${on ? 'Unfavourite' : 'Favourite'} ${fileName}`}
      disabled={busy}
      onClick={toggle}
    >
      <i className={`bi ${on ? 'bi-star-fill' : 'bi-star'}`} aria-hidden="true" />
    </button>
  );
}
