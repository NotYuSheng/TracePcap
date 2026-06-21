import { useCallback, useEffect, useState } from 'react';
import { monitorService } from '@/features/monitor/services/monitorService';
import { insightsService } from '@/features/insights/services/insightsService';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';
import type {
  Network,
  NetworkSnapshot,
  ChangeEvent,
  BaselineDefinition,
  BaselineEntryType,
  SubnetOverrideInput,
} from '@/features/monitor/types/monitor.types';
import type {
  NetworkExternalEvent,
  NetworkAnnotation,
  NetworkInsight,
  InsightOptions,
} from '@/features/insights/types/insights.types';

/**
 * Owns all server state for the network detail page — the initial parallel load,
 * background polling, and every mutation handler — so the page component is left
 * to compose presentation. Mutations update local state optimistically where the
 * service returns the updated entity, and fall back to a full reload otherwise.
 */
export function useNetworkDetailData(networkId: string | undefined) {
  const [network, setNetwork] = useState<Network | null>(null);
  const [snapshots, setSnapshots] = useState<NetworkSnapshot[]>([]);
  const [changeEvents, setChangeEvents] = useState<ChangeEvent[]>([]);
  const [definitions, setDefinitions] = useState<BaselineDefinition[]>([]);
  const [externalEvents, setExternalEvents] = useState<NetworkExternalEvent[]>([]);
  const [annotations, setAnnotations] = useState<NetworkAnnotation[]>([]);
  const [insight, setInsight] = useState<NetworkInsight | null>(null);
  const [subnets, setSubnets] = useState<SubnetDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [pollInterval, setPollInterval] = useState(30); // seconds

  const loadAll = useCallback(async (showSpinner = false) => {
    if (!networkId) {
      setLoading(false);
      return;
    }
    if (showSpinner) setLoading(true);
    try {
      const [net, snaps, events, defs, evts, annots, ins, subs] = await Promise.all([
        monitorService.getNetwork(networkId),
        monitorService.listSnapshots(networkId),
        monitorService.listChanges(networkId),
        monitorService.listDefinitions(networkId),
        insightsService.listExternalEvents(networkId),
        insightsService.listAnnotations(networkId),
        insightsService.getLatestInsight(networkId),
        subnetService.list(),
      ]);
      setNetwork(net);
      setSnapshots(snaps);
      setChangeEvents(events);
      setDefinitions(defs);
      setExternalEvents(evts);
      setAnnotations(annots);
      setInsight(ins);
      setSubnets(subs);
      setLastUpdated(new Date());
    } catch {
      setError('Failed to load network data.');
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [networkId]);

  useEffect(() => {
    loadAll(true);
    if (pollInterval === 0) return;
    const interval = setInterval(() => loadAll(false), pollInterval * 1000);
    return () => clearInterval(interval);
  }, [loadAll, pollInterval]);

  const handleAddSnapshot = async (fileId: string, subnetOverrides?: SubnetOverrideInput[]) => {
    if (!networkId) return;
    await monitorService.addSnapshot(networkId, fileId, subnetOverrides);
    await loadAll(false);
  };

  const handleRemoveSnapshot = async (snapshotId: string) => {
    if (!networkId) return;
    await monitorService.removeSnapshot(networkId, snapshotId);
    await loadAll(false);
  };

  const handleSnapshotUpdated = (updated: NetworkSnapshot) => {
    setSnapshots(prev => prev.map(s => s.id === updated.id ? updated : s));
  };

  const handleAddDefinition = async (
    entryType: BaselineEntryType,
    entityKey: string,
    entityValue?: string,
    notes?: string,
  ) => {
    if (!networkId) return;
    const def = await monitorService.createDefinition(networkId, entryType, entityKey, entityValue, notes);
    setDefinitions(prev => [...prev, def]);
  };

  const handleDeleteDefinition = async (id: string) => {
    if (!networkId) return;
    await monitorService.deleteDefinition(networkId, id);
    setDefinitions(prev => prev.filter(d => d.id !== id));
  };

  const handleAddExternalEvent = async (eventTime: string, title: string, description?: string) => {
    if (!networkId) return;
    const ev = await insightsService.createExternalEvent(networkId, eventTime, title, description);
    setExternalEvents(prev => [ev, ...prev]);
  };

  const handleUpdateExternalEvent = async (
    eventId: string,
    eventTime: string,
    title: string,
    description?: string,
  ) => {
    if (!networkId) return;
    const ev = await insightsService.updateExternalEvent(networkId, eventId, eventTime, title, description);
    setExternalEvents(prev =>
      prev
        .map(e => (e.id === eventId ? ev : e))
        .sort((a, b) => new Date(b.eventTime).getTime() - new Date(a.eventTime).getTime()),
    );
  };

  const handleDeleteExternalEvent = async (eventId: string) => {
    if (!networkId) return;
    await insightsService.deleteExternalEvent(networkId, eventId);
    setExternalEvents(prev => prev.filter(e => e.id !== eventId));
  };

  const handleAddAnnotation = async (body: string) => {
    if (!networkId) return;
    const a = await insightsService.createAnnotation(networkId, body);
    setAnnotations(prev => [a, ...prev]);
  };

  const handleUpdateAnnotation = async (annotationId: string, body: string) => {
    if (!networkId) return;
    const updated = await insightsService.updateAnnotation(networkId, annotationId, body);
    setAnnotations(prev => prev.map(a => a.id === updated.id ? updated : a));
  };

  const handleDeleteAnnotation = async (annotationId: string) => {
    if (!networkId) return;
    await insightsService.deleteAnnotation(networkId, annotationId);
    setAnnotations(prev => prev.filter(a => a.id !== annotationId));
  };

  const handleGenerateInsights = async (options: InsightOptions) => {
    if (!networkId) return;
    const ins = await insightsService.generateInsights(networkId, options);
    setInsight(ins);
  };

  const handleSubnetSaved = (subnet: SubnetDefinition) => {
    setSubnets(prev => {
      const idx = prev.findIndex(s => s.cidr === subnet.cidr);
      return idx >= 0 ? prev.map(s => s.cidr === subnet.cidr ? subnet : s) : [...prev, subnet];
    });
  };

  const handleSubnetDeleted = (id: number) => {
    setSubnets(prev => prev.filter(s => s.id !== id));
  };

  const handlePatchChange = async (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => {
    if (!networkId) return;
    try {
      const updated = await monitorService.patchChange(networkId, eventId, patch);
      setChangeEvents(prev => prev.map(e => e.id === updated.id ? updated : e));
    } catch (err) {
      console.error('Failed to patch change event:', err);
      throw err;
    }
  };

  return {
    // state
    network,
    snapshots,
    changeEvents,
    definitions,
    externalEvents,
    annotations,
    insight,
    subnets,
    loading,
    error,
    lastUpdated,
    pollInterval,
    setPollInterval,
    // actions
    reload: loadAll,
    handleAddSnapshot,
    handleRemoveSnapshot,
    handleSnapshotUpdated,
    handleAddDefinition,
    handleDeleteDefinition,
    handleAddExternalEvent,
    handleUpdateExternalEvent,
    handleDeleteExternalEvent,
    handleAddAnnotation,
    handleUpdateAnnotation,
    handleDeleteAnnotation,
    handleGenerateInsights,
    handleSubnetSaved,
    handleSubnetDeleted,
    handlePatchChange,
  };
}
