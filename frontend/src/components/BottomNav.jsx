import { NavLink } from 'react-router-dom';
import { Home, Search, Clock, FileText } from 'lucide-react';
import { useIsMobile } from '../hooks/useMediaQuery.jsx';

// BottomNav — fixed bottom navigation, mobile only (<640px). Four destinations
// with the active route highlighted in accent green.

const ITEMS = [
  { to: '/dashboard', label: 'Home', Icon: Home },
  { to: '/scan/new', label: 'Scan', Icon: Search },
  { to: '/reports', label: 'Reports', Icon: FileText },
];

export function BottomNav() {
  const isMobile = useIsMobile();
  if (!isMobile) return null;

  return (
    <nav className="fixed inset-x-0 bottom-0 z-40 flex items-stretch border-t border-border bg-bg-subtle/95 backdrop-blur sm:hidden">
      {ITEMS.map(({ to, label, Icon }) => (
        <NavLink
          key={to}
          to={to}
          className={({ isActive }) =>
            `flex flex-1 flex-col items-center gap-0.5 py-2.5 font-mono text-[10px] ${
              isActive ? 'text-accent' : 'text-fg-muted'
            }`
          }
        >
          {({ isActive }) => (
            <>
              <Icon size={20} />
              <span>{label}</span>
              {isActive && <span className="absolute bottom-0 h-0.5 w-8 rounded-full bg-accent" />}
            </>
          )}
        </NavLink>
      ))}
    </nav>
  );
}

export default BottomNav;
