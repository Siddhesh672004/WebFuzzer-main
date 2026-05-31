import { useState, useEffect } from 'react';

// useMediaQuery — subscribe to a CSS media query and return whether it matches.
// SSR-safe (defaults to false when window is unavailable) and cleans up its
// listener on unmount. Used for responsive layout decisions (BottomNav, sheets).

export function useMediaQuery(query) {
  const get = () =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia(query).matches
      : false;

  const [matches, setMatches] = useState(get);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    const mql = window.matchMedia(query);
    const onChange = () => setMatches(mql.matches);
    onChange();
    // addEventListener is the modern API; fall back to addListener for Safari <14.
    if (mql.addEventListener) mql.addEventListener('change', onChange);
    else mql.addListener(onChange);
    return () => {
      if (mql.removeEventListener) mql.removeEventListener('change', onChange);
      else mql.removeListener(onChange);
    };
  }, [query]);

  return matches;
}

/** Convenience: true on phone-width viewports (<640px). */
export function useIsMobile() {
  return useMediaQuery('(max-width: 639px)');
}

export default useMediaQuery;
