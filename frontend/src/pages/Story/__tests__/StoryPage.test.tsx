import { render, screen } from '@testing-library/react';
import { useOutletContext } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { StoryPage } from '../StoryPage';

vi.mock('react-router-dom', async importOriginal => ({
  ...(await importOriginal<typeof import('react-router-dom')>()),
  useOutletContext: vi.fn(),
}));
vi.mock('@/features/timeline/services/timelineService', () => ({
  timelineService: { getTimelineData: vi.fn().mockResolvedValue([]) },
}));
vi.mock('@/features/story/services/storyService', () => ({
  storyService: {
    getInvestigation: vi.fn().mockResolvedValue({ answers: [], unknowns: [] }),
  },
}));
vi.mock('@components/story/NarrativeView', () => ({
  NarrativeView: () => <div>narrative</div>,
}));
vi.mock('@components/story/StoryTimeline', () => ({ StoryTimeline: () => null }));
vi.mock('@components/story/StorySectionNav/StorySectionNav', () => ({
  StorySectionNav: () => null,
}));
vi.mock('@components/story/StoryProgress/StoryProgress', () => ({
  StoryProgress: () => <div>generating</div>,
}));
vi.mock('@components/story/ConfirmedFindingsPanel/ConfirmedFindingsPanel', () => ({
  ConfirmedFindingsPanel: () => null,
}));
vi.mock('@components/story/StoryInfoCard', () => ({ StoryInfoCard: () => null }));
vi.mock('@components/story/StoryChat', () => ({ StoryChat: () => null }));
vi.mock('@components/story/AggregatesPanel', () => ({ AggregatesPanel: () => null }));
vi.mock('@components/story/FindingsPanel', () => ({ FindingsPanel: () => null }));
vi.mock('@components/story/InvestigationPanel', () => ({ InvestigationPanel: () => null }));
vi.mock('@components/timeline/TrafficTimeline', () => ({ TrafficTimeline: () => null }));

const storyState = (overrides: Record<string, unknown>) => ({
  story: null,
  generating: false,
  error: null,
  contextError: null,
  setContextError: vi.fn(),
  editablePrompt: '',
  setEditablePrompt: vi.fn(),
  elapsedSeconds: 0,
  llmTimeoutMs: 60_000,
  generateStory: vi.fn(),
  additionalContext: '',
  setAdditionalContext: vi.fn(),
  maxFindings: 10,
  setMaxFindings: vi.fn(),
  maxRiskMatrix: 10,
  setMaxRiskMatrix: vi.fn(),
  totalFindings: 0,
  totalRiskMatrix: 0,
  ...overrides,
});

const withStoryState = (overrides: Record<string, unknown>) =>
  vi.mocked(useOutletContext).mockReturnValue({
    fileId: 'file-1',
    storyState: storyState(overrides),
  });

describe('StoryPage', () => {
  it('survives a story arriving while the page is open', async () => {
    withStoryState({ generating: true });
    const { rerender } = render(<StoryPage />);
    expect(screen.getByText('generating')).toBeInTheDocument();

    withStoryState({ story: { id: 'story-1', narrative: [] } });
    rerender(<StoryPage />);

    expect(await screen.findByText('narrative')).toBeInTheDocument();
  });
});
