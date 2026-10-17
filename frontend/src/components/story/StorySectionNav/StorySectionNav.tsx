import { useEffect, useState } from 'react';

export interface StorySection {
  id: string;
  label: string;
  icon: string;
}

interface StorySectionNavProps {
  sections: StorySection[];
}

/**
 * Sticky in-page navigation for the (long) Story page: a list of the sections actually present,
 * each jumping to its anchor, with the section nearest the top highlighted as you scroll. Only the
 * sections passed in are shown, so it stays in sync with what the page conditionally renders.
 */
export function StorySectionNav({ sections }: StorySectionNavProps) {
  const [activeId, setActiveId] = useState<string>(sections[0]?.id ?? '');

  useEffect(() => {
    if (sections.length === 0) return;
    const observer = new IntersectionObserver(
      entries => {
        const visible = entries
          .filter(e => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible.length > 0) setActiveId(visible[0].target.id);
      },
      // Bias the "active" band toward the top of the viewport, below any sticky header.
      { rootMargin: '-80px 0px -55% 0px', threshold: 0 }
    );
    sections.forEach(s => {
      const el = document.getElementById(s.id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [sections]);

  const jump = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setActiveId(id);
  };

  return (
    <nav aria-label="Story sections">
      {/* Reuses the app's nav-link styling (same as the Analysis page tabs), laid out vertically. */}
      <ul className="nav nav-pills flex-column">
        {sections.map(s => (
          <li className="nav-item" key={s.id}>
            <button
              type="button"
              onClick={() => jump(s.id)}
              className={`nav-link text-start w-100 d-flex align-items-start ${s.id === activeId ? 'active' : ''}`}
            >
              <i className={`bi ${s.icon} me-2`} aria-hidden="true" />
              <span>{s.label}</span>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}
