import { useEffect, useState } from 'react';
import { Form } from '@govtechsg/sgds-react';
import { Link } from 'react-router-dom';
import { monitorService } from '@/features/monitor/services/monitorService';
import { detectionRulesService } from './detectionRulesService';
import { useNetworkContext } from './useNetworkContext';

interface NetworkRef {
  id: string;
  name: string;
}

/**
 * "Custom detection rules" (#925 phase 3; was "Viewing with"): view the capture with only its global and capture rules (the
 * default), or in a network, adding that network's rules. Lists the networks the capture is in
 * first, then the rest.
 */
export function NetworkContextPicker({ fileId }: { fileId: string }) {
  const [networkId, setNetworkId] = useNetworkContext();
  const [mine, setMine] = useState<NetworkRef[]>([]);
  const [others, setOthers] = useState<NetworkRef[]>([]);

  useEffect(() => {
    let active = true;
    Promise.all([
      detectionRulesService.captureNetworks(fileId).catch(() => [] as NetworkRef[]),
      monitorService.listNetworks().catch(() => []),
    ]).then(([inThem, all]) => {
      if (!active) return;
      const ids = new Set(inThem.map(n => n.id));
      setMine(inThem);
      setOthers(all.filter(n => !ids.has(n.id)).map(n => ({ id: n.id, name: n.name })));
    });
    return () => {
      active = false;
    };
  }, [fileId]);

  if (mine.length === 0 && others.length === 0 && !networkId) return null;
  const known = [...mine, ...others].some(n => n.id === networkId);

  return (
    <div className="d-flex flex-wrap align-items-center gap-2 small">
      <Form.Label htmlFor="network-context" className="mb-0 text-muted">
        <i className="bi bi-shield-check me-1" aria-hidden="true" />
        Custom detection rules
      </Form.Label>
      <Form.Select
        id="network-context"
        size="sm"
        style={{ width: 'auto', maxWidth: 360 }}
        value={networkId ?? ''}
        onChange={e => setNetworkId(e.target.value || undefined)}
      >
        <option value="">Global and capture rules only</option>
        {mine.length > 0 && (
          <optgroup label="Networks with this capture">
            {mine.map(n => (
              <option key={n.id} value={n.id}>
                {n.name}'s rules too
              </option>
            ))}
          </optgroup>
        )}
        {others.length > 0 && (
          <optgroup label="Other networks">
            {others.map(n => (
              <option key={n.id} value={n.id}>
                {n.name}'s rules too
              </option>
            ))}
          </optgroup>
        )}
        {networkId && !known && <option value={networkId}>A network that no longer exists</option>}
      </Form.Select>
      {!networkId && mine.length > 0 && (
        <span className="text-muted" data-testid="network-context-hint">
          This capture is in {mine.map(n => n.name).join(', ')}: pick it to include that network's rules.
        </span>
      )}
      <span className="text-muted">
        Create custom rules in <Link to="/settings?tab=rules">Settings › Detection rules</Link>.
      </span>
    </div>
  );
}
