import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * The network the Analysis page is viewed in (#925 phase 3), from `?networkId=`. With one, that
 * network's own detection rules' matches show too. Setting it keeps every other query parameter.
 */
export function useNetworkContext(): [string | undefined, (networkId?: string) => void] {
  const [params, setParams] = useSearchParams();
  const networkId = params.get('networkId') ?? undefined;
  const set = useCallback(
    (id?: string) =>
      setParams(
        prev => {
          const next = new URLSearchParams(prev);
          if (id) next.set('networkId', id);
          else next.delete('networkId');
          next.delete('page'); // results change, so start from the first page
          return next;
        },
        { replace: true }
      ),
    [setParams]
  );
  return [networkId, set];
}
