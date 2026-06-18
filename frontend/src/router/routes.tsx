import { createBrowserRouter } from 'react-router-dom';
import { MainLayout } from '@components/common/Layout';
import { RouteErrorBoundary } from '@components/common/RouteErrorBoundary';
import { UploadPage } from '@pages/Upload';
import { AnalysisPage } from '@pages/Analysis';
import { AnalysisOverview } from '@pages/Analysis/AnalysisOverview';
import { ConversationPage } from '@pages/Conversation';
import { StoryPage } from '@pages/Story';
import { FilterGeneratorPage } from '@pages/FilterGenerator';
import { NetworkDiagramPage } from '@pages/NetworkDiagram';
import { ExtractedFilesPage } from '@pages/ExtractedFiles';
import { ComparePage } from '@pages/Compare/ComparePage';
import { NetworkIntelligencePage } from '@pages/NetworkIntelligence';
import { NotFoundPage } from '@pages/NotFound';
import { MonitorPage } from '@pages/Monitor/MonitorPage';
import { NetworkDetailPage } from '@pages/Monitor/NetworkDetailPage';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <MainLayout />,
    errorElement: <RouteErrorBoundary />,
    children: [
      {
        index: true,
        element: <UploadPage />,
      },
      {
        path: 'analysis/:fileId',
        element: <AnalysisPage />,
        errorElement: <RouteErrorBoundary />,
        children: [
          {
            index: true,
            element: <AnalysisOverview />,
          },
          {
            path: 'conversations',
            element: <ConversationPage />,
          },
          {
            path: 'story',
            element: <StoryPage />,
          },
          {
            path: 'filter-generator',
            element: <FilterGeneratorPage />,
          },
          {
            path: 'network-diagram',
            element: <NetworkDiagramPage />,
          },
          {
            path: 'extracted-files',
            element: <ExtractedFilesPage />,
          },
          {
            path: 'network-intelligence',
            element: <NetworkIntelligencePage />,
          },
        ],
      },
      {
        path: 'compare',
        element: <ComparePage />,
      },
      {
        path: 'monitor',
        element: <MonitorPage />,
      },
      {
        path: 'monitor/:networkId',
        element: <NetworkDetailPage />,
      },
      {
        path: '*',
        element: <NotFoundPage />,
      },
    ],
  },
]);
