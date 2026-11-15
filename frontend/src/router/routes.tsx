import { Navigate, createBrowserRouter, useLocation } from 'react-router-dom';
import { MainLayout } from '@components/common/Layout';
import { RouteErrorBoundary } from '@components/common/RouteErrorBoundary';
import { HomePage } from '@pages/Home';
import { AnalysisPage } from '@pages/Analysis';
import { AnalysisOverview } from '@pages/Analysis/AnalysisOverview';
import { ConversationPage } from '@pages/Conversation';
import { StoryPage } from '@pages/Story';
import { FilterGeneratorPage } from '@pages/FilterGenerator';
import { NetworkDiagramPage } from '@pages/NetworkDiagram';
import { ExtractedFilesPage } from '@pages/ExtractedFiles';
import { ComparePage } from '@pages/Compare/ComparePage';
import { FileTabPage } from '@pages/Analysis/FileTabPage';
import { NotFoundPage } from '@pages/NotFound';
import { MonitorPage } from '@pages/Monitor/MonitorPage';
import { NetworkDetailPage } from '@pages/Monitor/NetworkDetailPage';
import { SystemPage } from '@pages/System';

/** /system (and /system?tab=…) to the Settings page it became. */
function SystemRedirect() {
  const { search } = useLocation();
  return <Navigate to={`/settings${search}`} replace />;
}

export const router = createBrowserRouter([
  {
    path: '/',
    element: <MainLayout />,
    errorElement: <RouteErrorBoundary />,
    children: [
      {
        index: true,
        element: <HomePage />,
      },
      {
        path: 'analysis/:fileId',
        element: <AnalysisPage />,
        errorElement: <RouteErrorBoundary />,
        // errorElement on each child tab so a throw renders inside AnalysisPage's
        // <Outlet> (keeping the header/tabs), instead of replacing the whole shell.
        children: [
          {
            index: true,
            element: <AnalysisOverview />,
            errorElement: <RouteErrorBoundary />,
          },
          {
            path: 'conversations',
            element: <ConversationPage />,
            errorElement: <RouteErrorBoundary />,
          },
          {
            path: 'story',
            element: <StoryPage />,
            errorElement: <RouteErrorBoundary />,
          },
          {
            path: 'filter-generator',
            element: <FilterGeneratorPage />,
            errorElement: <RouteErrorBoundary />,
          },
          {
            path: 'network-diagram',
            element: <NetworkDiagramPage />,
            errorElement: <RouteErrorBoundary />,
          },
          {
            path: 'file',
            element: <FileTabPage />,
            errorElement: <RouteErrorBoundary />,
          },
          {
            path: 'extracted-files',
            element: <ExtractedFilesPage />,
            errorElement: <RouteErrorBoundary />,
          },
          {
            // The Cluster tab is folded into the Overview ("Where the traffic goes" and the flows
            // between organisations), now that the diagram draws every host. Old links, and the
            // even older network-intelligence ones (#745), land on the Overview.
            path: 'network-cluster',
            element: <Navigate to=".." replace />,
          },
          {
            path: 'network-intelligence',
            element: <Navigate to=".." replace />,
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
        path: 'settings',
        element: <SystemPage />,
      },
      {
        // The System page became Settings: old links still land there, tab and all.
        path: 'system',
        element: <SystemRedirect />,
      },
      {
        path: '*',
        element: <NotFoundPage />,
      },
    ],
  },
]);
