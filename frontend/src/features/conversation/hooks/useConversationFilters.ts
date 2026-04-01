import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { ConversationFilters, SortDir, SortField } from '../types';

function splitComma(value: string | null): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}

function joinComma(values: string[]): string | undefined {
  return values.length > 0 ? values.join(',') : undefined;
}

export function useConversationFilters() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Memoize so the object reference is stable as long as the URL hasn't changed.
  // This prevents ConversationPage's useEffect from firing on every render.
  const filters = useMemo(
    (): ConversationFilters => ({
      ip: searchParams.get('ip') ?? '',
      port: searchParams.get('port') ?? '',
      payloadContains: searchParams.get('payloadContains') ?? '',
      protocols: splitComma(searchParams.get('protocols')),
      l7Protocols: splitComma(searchParams.get('l7Protocols')),
      apps: splitComma(searchParams.get('apps')),
      categories: splitComma(searchParams.get('categories')),
      hasRisks: searchParams.get('hasRisks') === 'true',
      fileTypes: splitComma(searchParams.get('fileTypes')),
      riskTypes: splitComma(searchParams.get('riskTypes')),
      customSignatures: splitComma(searchParams.get('customSignatures')),
      deviceTypes: splitComma(searchParams.get('deviceTypes')),
      countries: splitComma(searchParams.get('countries')),
      sortBy: (searchParams.get('sortBy') ?? '') as SortField,
      sortDir: (searchParams.get('sortDir') ?? 'asc') as SortDir,
      page: Math.max(1, parseInt(searchParams.get('page') ?? '1')),
      pageSize: parseInt(searchParams.get('pageSize') ?? '25'),
    }),
    [searchParams]
  );

  const activeFilterCount = useMemo(
    () =>
      [
        filters.ip,
        filters.port,
        filters.payloadContains,
        filters.protocols.length > 0,
        filters.l7Protocols.length > 0,
        filters.apps.length > 0,
        filters.categories.length > 0,
        filters.hasRisks,
        filters.fileTypes.length > 0,
        filters.riskTypes.length > 0,
        filters.customSignatures.length > 0,
        filters.deviceTypes.length > 0,
        filters.countries.length > 0,
      ].filter(Boolean).length,
    [filters]
  );

  // setFilters reads from the prev URLSearchParams inside the setter callback
  // so it doesn't need to capture `filters` and stays stable.
  const setFilters = useCallback(
    (update: Partial<ConversationFilters>) => {
      setSearchParams(prev => {
        const next = new URLSearchParams(prev);

        const cur: ConversationFilters = {
          ip: prev.get('ip') ?? '',
          port: prev.get('port') ?? '',
          payloadContains: prev.get('payloadContains') ?? '',
          protocols: splitComma(prev.get('protocols')),
          l7Protocols: splitComma(prev.get('l7Protocols')),
          apps: splitComma(prev.get('apps')),
          categories: splitComma(prev.get('categories')),
          hasRisks: prev.get('hasRisks') === 'true',
          fileTypes: splitComma(prev.get('fileTypes')),
          riskTypes: splitComma(prev.get('riskTypes')),
          customSignatures: splitComma(prev.get('customSignatures')),
          deviceTypes: splitComma(prev.get('deviceTypes')),
          countries: splitComma(prev.get('countries')),
          sortBy: (prev.get('sortBy') ?? '') as SortField,
          sortDir: (prev.get('sortDir') ?? 'asc') as SortDir,
          page: Math.max(1, parseInt(prev.get('page') ?? '1')),
          pageSize: parseInt(prev.get('pageSize') ?? '25'),
        };

        const merged = { ...cur, ...update };
        const newPage = update.page ?? 1;

        const set = (key: string, val: string | undefined) => {
          if (val) next.set(key, val);
          else next.delete(key);
        };

        set('ip', merged.ip || undefined);
        set('port', merged.port || undefined);
        set('payloadContains', merged.payloadContains || undefined);
        set('protocols', joinComma(merged.protocols));
        set('l7Protocols', joinComma(merged.l7Protocols));
        set('apps', joinComma(merged.apps));
        set('categories', joinComma(merged.categories));
        set('hasRisks', merged.hasRisks ? 'true' : undefined);
        set('fileTypes', joinComma(merged.fileTypes));
        set('riskTypes', joinComma(merged.riskTypes));
        set('customSignatures', joinComma(merged.customSignatures));
        set('deviceTypes', joinComma(merged.deviceTypes ?? []));
        set('countries', joinComma(merged.countries ?? []));
        set('sortBy', merged.sortBy || undefined);
        set('sortDir', merged.sortBy ? merged.sortDir : undefined);
        set('page', newPage > 1 ? String(newPage) : undefined);
        set('pageSize', merged.pageSize !== 25 ? String(merged.pageSize) : undefined);

        return next;
      }, { replace: true });
    },
    [setSearchParams]
  );

  const clearAll = useCallback(() => setSearchParams({}, { replace: true }), [setSearchParams]);

  return { filters, activeFilterCount, setFilters, clearAll };
}
