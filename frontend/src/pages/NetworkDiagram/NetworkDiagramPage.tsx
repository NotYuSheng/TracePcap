import { useOutletContext } from 'react-router-dom';
import type { AnalysisOutletContext } from '@/pages/Analysis/AnalysisPage';
import { NetworkDiagramView } from './NetworkDiagramView';

/** The analysis page's Network tab: the network diagram for the capture being analysed. */
export const NetworkDiagramPage = () => {
  const { fileId, data, networkGraphStateRef, networkDiagramFilters } =
    useOutletContext<AnalysisOutletContext>();
  return (
    <NetworkDiagramView
      fileId={fileId}
      data={data}
      networkGraphStateRef={networkGraphStateRef}
      networkDiagramFilters={networkDiagramFilters}
    />
  );
};
