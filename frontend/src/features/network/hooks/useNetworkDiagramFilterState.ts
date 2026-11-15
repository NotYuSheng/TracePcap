import { useState } from 'react';
import { MAX_DIAGRAM_NODES } from '@/features/network/hooks/useNetworkData';
import type { NetworkDiagramFilterState } from '@/pages/Analysis/AnalysisPage';

/**
 * The network diagram's filters (node limit, address, port, chips). The analysis page holds one so
 * it survives tab switches; a Monitor capture holds its own.
 */
export function useNetworkDiagramFilterState(): NetworkDiagramFilterState {
  const [nodeLimit, setNodeLimit] = useState(MAX_DIAGRAM_NODES);
  const [ipFilter, setIpFilter] = useState('');
  const [portFilter, setPortFilter] = useState('');
  const [hasRisksOnly, setHasRisksOnly] = useState(false);
  const [activeLegendProtocols, setActiveLegendProtocols] = useState<string[]>([]);
  const [activeNodeFilters, setActiveNodeFilters] = useState<string[]>([]);
  const [activeAppFilters, setActiveAppFilters] = useState<string[]>([]);
  const [activeL7Protocols, setActiveL7Protocols] = useState<string[]>([]);
  const [activeCategories, setActiveCategories] = useState<string[]>([]);
  const [activeRiskTypes, setActiveRiskTypes] = useState<string[]>([]);
  const [activeCustomSigs, setActiveCustomSigs] = useState<string[]>([]);
  const [activeFileTypes, setActiveFileTypes] = useState<string[]>([]);
  const [activeCountries, setActiveCountries] = useState<string[]>([]);
  const [activeGhostFilters, setActiveGhostFilters] = useState<string[]>([]);

  return {
    nodeLimit,
    setNodeLimit,
    ipFilter,
    setIpFilter,
    portFilter,
    setPortFilter,
    hasRisksOnly,
    setHasRisksOnly,
    activeLegendProtocols,
    setActiveLegendProtocols,
    activeNodeFilters,
    setActiveNodeFilters,
    activeAppFilters,
    setActiveAppFilters,
    activeL7Protocols,
    setActiveL7Protocols,
    activeCategories,
    setActiveCategories,
    activeRiskTypes,
    setActiveRiskTypes,
    activeCustomSigs,
    setActiveCustomSigs,
    activeFileTypes,
    setActiveFileTypes,
    activeCountries,
    setActiveCountries,
    activeGhostFilters,
    setActiveGhostFilters,
  };
}
