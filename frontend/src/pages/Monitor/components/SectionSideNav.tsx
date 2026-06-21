import { useEffect, useState } from 'react';
import { SideNav } from '@govtechsg/sgds-react';

export interface SectionDef {
  id: string;
  label: string;
  icon: string;
}

/**
 * Sticky in-page navigation for the (long) network detail page. Renders one
 * SideNav.Link per visible section and tracks which section is in view via an
 * IntersectionObserver so the active link stays in sync while scrolling.
 */
export const SectionSideNav = ({ sections }: { sections: SectionDef[] }) => {
  const [active, setActive] = useState(sections[0]?.id ?? '');
  // Stable dependency: the effect only needs to re-run when the set of section
  // ids changes (e.g. the Traffic Overview section appears once 2+ snapshots
  // exist), not on every parent re-render from polling.
  const sectionIds = sections.map(s => s.id).join('|');

  useEffect(() => {
    const ids = sectionIds.split('|').filter(Boolean);
    const els = ids
      .map(id => document.getElementById(id))
      .filter((el): el is HTMLElement => el !== null);
    if (els.length === 0) return;

    // The observer callback only reports sections whose visibility *changed*,
    // so track the full visible set and pick the topmost one each time.
    const visibleIds = new Set<string>();

    const pickActive = () => {
      // At the very bottom the last section may be too short to ever reach the
      // active band (capped at 45% of the viewport), so force it active there.
      const atBottom =
        window.innerHeight + window.scrollY >=
        document.documentElement.scrollHeight - 2;
      if (atBottom) {
        setActive(ids[ids.length - 1]);
        return;
      }
      let topId: string | null = null;
      let topY = Infinity;
      visibleIds.forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        const y = el.getBoundingClientRect().top;
        if (y < topY) {
          topY = y;
          topId = id;
        }
      });
      if (topId) setActive(topId);
    };

    const observer = new IntersectionObserver(
      entries => {
        for (const e of entries) {
          if (e.isIntersecting) visibleIds.add(e.target.id);
          else visibleIds.delete(e.target.id);
        }
        pickActive();
      },
      // Top boundary sits just above where an anchored section lands
      // (scroll-margin-top: 124px), so a clicked section counts as active.
      // The -55% bottom margin keeps the "active" band in the upper viewport.
      { rootMargin: '-116px 0px -55% 0px', threshold: 0 },
    );
    els.forEach(el => observer.observe(el));

    // Catch the bottom-of-page case, where intersection state may not change.
    window.addEventListener('scroll', pickActive, { passive: true });
    return () => {
      observer.disconnect();
      window.removeEventListener('scroll', pickActive);
    };
  }, [sectionIds]);

  const handleClick = (e: React.MouseEvent<HTMLElement>, id: string) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setActive(id);
    }
  };

  return (
    <SideNav sticky activeNavLinkKey={active} className="tp-section-nav">
      {sections.map(s => (
        <SideNav.Link
          key={s.id}
          eventKey={s.id}
          href={`#${s.id}`}
          onClick={(e: React.MouseEvent<HTMLElement>) => handleClick(e, s.id)}
        >
          <i className={`bi ${s.icon} me-2`}></i>
          {s.label}
        </SideNav.Link>
      ))}
    </SideNav>
  );
};
