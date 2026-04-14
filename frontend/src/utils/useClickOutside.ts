import { useEffect, type RefObject } from 'react';

/**
 * Closes a popup/panel when the user clicks outside the given ref element.
 * Attach the ref to the container you want to protect, then pass onClose.
 */
export function useClickOutside(ref: RefObject<HTMLElement | null>, onClose: () => void): void {
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [ref, onClose]);
}
