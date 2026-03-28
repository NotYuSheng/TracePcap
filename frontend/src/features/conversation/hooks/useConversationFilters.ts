import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { ConversationFilters, SortDir, SortField } from '../types';

function splitComma(value: string | null): string[] {
  if (!value) return [];
  return value.split(',').map(s => s.trim()).filter(Boolean);
}

function joinComma(values: string[]): string | undefined {
  return values.length > 0 ? values.join(',') : undefined;
}

export function useConversationFilters() {
  const [searchParams, setSearchParams] = useSearchParams();

  const filters: ConversationFilters = {
    ip:         searchParams.get('ip') ?? '',
    protocols:  splitComma(searchParams.get('protocols')),
    apps:       splitComma(searchParams.get('apps')),
    categories: splitComma(searchParams.get('categories')),
    hasRisks:   searchParams.get('hasRisks') === 'true',
    sortBy:     (searchParams.get('sortBy') ?? '') as SortField,
    sortDir:    (searchParams.get('sortDir') ?? 'asc') as SortDir,
    page:       Math.max(1, parseInt(searchParams.get('page') ?? '1')),
    pageSize:   parseInt(searchParams.get('pageSize') ?? '25'),
  };

  const activeFilterCount = [
    filters.ip,
    filters.protocols.length > 0,
    filters.apps.length > 0,
    filters.categories.length > 0,
    filters.hasRisks,
  ].filter(Boolean).length;

  const setFilters = useCallback((update: Partial<ConversationFilters>) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      const merged = { ...filters, ...update };

      // Always reset to page 1 when any filter changes (unless page is explicitly set)
      const newPage = update.page ?? 1;

      const set = (key: string, val: string | undefined) => {
        if (val) next.set(key, val); else next.delete(key);
      };

      set('ip',         merged.ip || undefined);
      set('protocols',  joinComma(merged.protocols));
      set('apps',       joinComma(merged.apps));
      set('categories', joinComma(merged.categories));
      set('hasRisks',   merged.hasRisks ? 'true' : undefined);
      set('sortBy',     merged.sortBy || undefined);
      set('sortDir',    merged.sortBy ? merged.sortDir : undefined);
      set('page',       newPage > 1 ? String(newPage) : undefined);
      set('pageSize',   merged.pageSize !== 25 ? String(merged.pageSize) : undefined);

      return next;
    });
  }, [filters, setSearchParams]);

  const clearAll = useCallback(() => setSearchParams({}), [setSearchParams]);

  return { filters, activeFilterCount, setFilters, clearAll };
}
