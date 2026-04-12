import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import type { StoryTimelineEvent } from '@/types';
import { formatTimestamp } from '@/utils/formatters';

function InfoPopover() {
  const popover = (
    <Popover id="info-event-timeline" style={{ maxWidth: '320px' }}>
      <Popover.Header>Event Timeline — How it works</Popover.Header>
      <Popover.Body className="small">
        <p className="mb-2">
          Timeline events are extracted by the LLM from the evidence it was given — at-risk
          conversations and pre-computed aggregates. Events are sorted chronologically by the
          timestamp the LLM assigned to each.
        </p>
        <p className="mb-2">
          <strong>Limitations:</strong>
        </p>
        <ul className="mb-0 ps-3">
          <li>
            Timestamps are estimated by the LLM and may not exactly match packet-level timing.
          </li>
          <li>
            Only activity visible in the evidence sample is represented — benign or low-volume flows
            may be absent.
          </li>
          <li>
            Event classification (normal / suspicious / critical) reflects the LLM's judgment, not a
            deterministic rule.
          </li>
        </ul>
      </Popover.Body>
    </Popover>
  );
  return (
    <OverlayTrigger trigger="click" placement="right" overlay={popover} rootClose>
      <button
        type="button"
        className="btn btn-link p-0 text-muted ms-2"
        style={{ lineHeight: 1 }}
        aria-label="About Event Timeline"
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.9rem' }}></i>
      </button>
    </OverlayTrigger>
  );
}

interface StoryTimelineProps {
  events: StoryTimelineEvent[];
}

export const StoryTimeline = ({ events }: StoryTimelineProps) => {
  const getEventClass = (type: string) => {
    const classes: Record<string, string> = {
      normal: 'text-primary',
      suspicious: 'text-warning',
      critical: 'text-danger',
    };
    return classes[type] || 'text-secondary';
  };

  const getEventIcon = (type: string) => {
    const icons: Record<string, string> = {
      normal: 'bi-circle-fill',
      suspicious: 'bi-exclamation-circle-fill',
      critical: 'bi-x-circle-fill',
    };
    return icons[type] || 'bi-circle';
  };

  const sortedEvents = [...events].sort((a, b) => a.timestamp - b.timestamp);

  return (
    <div className="story-timeline">
      <h5 className="mb-4 d-flex align-items-center">
        Event Timeline
        <InfoPopover />
      </h5>

      <div className="timeline">
        {sortedEvents.map((event, index) => (
          <div key={index} className="timeline-item mb-4">
            <div className="d-flex">
              <div className="flex-shrink-0 me-3">
                <i className={`bi ${getEventIcon(event.type)} ${getEventClass(event.type)}`}></i>
              </div>
              <div className="flex-grow-1">
                <div className="d-flex justify-content-between align-items-start">
                  <h6
                    className={`mb-1 ${event.type === 'suspicious' || event.type === 'critical' ? getEventClass(event.type) : ''}`}
                  >
                    {event.title}
                  </h6>
                  <small className="text-muted">{formatTimestamp(event.timestamp)}</small>
                </div>
                <p className="mb-2 text-muted">{event.description}</p>
                {event.relatedData && (
                  <div className="mt-2">
                    <small className="text-muted">
                      {event.relatedData.conversations && (
                        <span className="me-3">
                          <i className="bi bi-chat me-1"></i>
                          {event.relatedData.conversations.length} conversation(s)
                        </span>
                      )}
                      {event.relatedData.packets && (
                        <span>
                          <i className="bi bi-box me-1"></i>
                          {event.relatedData.packets.length} packet(s)
                        </span>
                      )}
                    </small>
                  </div>
                )}
              </div>
            </div>
            {index < sortedEvents.length - 1 && (
              <div
                className="timeline-connector ms-2 my-2"
                style={{ height: '30px', borderLeft: '2px solid #dee2e6' }}
              ></div>
            )}
          </div>
        ))}
      </div>

      {events.length === 0 && (
        <div className="alert alert-secondary">
          <p className="mb-0">No timeline events to display</p>
        </div>
      )}
    </div>
  );
};
