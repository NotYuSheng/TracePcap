import { createBrowserRouter } from 'react-router-dom';
import { MainLayout } from '@components/common/Layout';
import { UploadPage } from '@pages/Upload';
import { AnalysisPage } from '@pages/Analysis';
import { AnalysisOverview } from '@pages/Analysis/AnalysisOverview';
import { ConversationPage } from '@pages/Conversation';
import { StoryPage } from '@pages/Story';
import { FilterGeneratorPage } from '@pages/FilterGenerator';
import { NetworkDiagramPage } from '@pages/NetworkDiagram';
import { NotFoundPage } from '@pages/NotFound';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <MainLayout />,
    children: [
      {
        index: true,
        element: <UploadPage />,
      },
      {
        path: 'analysis/:fileId',
        element: <AnalysisPage />,
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
        ],
      },
      {
        path: '*',
        element: <NotFoundPage />,
      },
    ],
  },
]);
