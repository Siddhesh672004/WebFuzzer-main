import { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { Shield, Home, Search, FileText, LogOut, PanelLeftClose, PanelLeft } from 'lucide-react';
import { useAuth, useLogout } from '../hooks/useAuth.js';
import { useMediaQuery } from '../hooks/useMediaQuery.jsx';
import { BottomNav } from './BottomNav.jsx';

// Layout — responsive app shell. Desktop (≥1024px): a collapsible sidebar +
// content. Tablet (640–1023px): icon-only sidebar. Mobile (<640px): content +
// BottomNav. Pages opt in by wrapping their body in <Layout>; the existing
// self-contained page headers also work without it, so adoption is incremental.

const NAV = [
  { to: '/dashboard', label: 'Dashboard', Icon: Home },
  { to: '/scan/new', label: 'New Scan', Icon: Search },
  { to: '/reports', label: 'Reports', Icon: FileText },
];

export function Layout({ children, title }) {
  const navigate = useNavigate();
  const { user } = useAuth();
  const logout = useLogout();
  const isDesktop = useMediaQuery('(min-width: 1024px)');
  const isMobile = useMediaQuery('(max-width: 639px)');
  const [collapsed, setCollapsed] = useState(false);

  // Tablet is always icon-only; desktop respects the collapse toggle.
  const iconOnly = !isMobile && (!isDesktop || collapsed);

  async function handleLogout() {
    await logout.mutateAsync().catch(() => {});
    navigate('/verify', { replace: true });
  }

  return (
    <div className="flex min-h-screen bg-bg">
      {/* Sidebar (hidden on mobile) */}
      {!isMobile && (
        <aside className={`flex shrink-0 flex-col border-r border-border bg-bg-subtle transition-all ${iconOnly ? 'w-16' : 'w-60'}`}>
          <div className="flex items-center gap-2 border-b border-border px-4 py-4">
            <Shield className="h-6 w-6 shrink-0 text-accent" />
            {!iconOnly && <span className="font-mono text-lg font-bold text-fg">Smart<span className="text-accent">Fuzz</span></span>}
          </div>

          <nav className="flex-1 space-y-1 p-2">
            {NAV.map(({ to, label, Icon }) => (
              <NavLink
                key={to}
                to={to}
                title={label}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-md px-3 py-2 font-mono text-sm transition-colors ${
                    isActive ? 'bg-accent/10 text-accent' : 'text-fg-muted hover:bg-bg hover:text-fg'
                  }`
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                {!iconOnly && <span>{label}</span>}
              </NavLink>
            ))}
          </nav>

          <div className="border-t border-border p-2">
            {isDesktop && (
              <button
                onClick={() => setCollapsed((v) => !v)}
                className="mb-1 flex w-full items-center gap-3 rounded-md px-3 py-2 font-mono text-xs text-fg-muted hover:bg-bg hover:text-fg"
              >
                {collapsed ? <PanelLeft className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
                {!iconOnly && <span>Collapse</span>}
              </button>
            )}
            <button
              onClick={handleLogout}
              title="Logout"
              className="flex w-full items-center gap-3 rounded-md px-3 py-2 font-mono text-sm text-fg-muted hover:bg-bg hover:text-fg"
            >
              <LogOut className="h-4 w-4 shrink-0" />
              {!iconOnly && <span className="truncate">{user?.email || 'Logout'}</span>}
            </button>
          </div>
        </aside>
      )}

      {/* Content */}
      <div className="flex min-w-0 flex-1 flex-col pb-16 sm:pb-0">
        {title && (
          <header className="border-b border-border bg-bg-subtle px-4 py-3">
            <h1 className="font-mono text-lg font-bold text-fg">{title}</h1>
          </header>
        )}
        <main className="flex-1">{children}</main>
      </div>

      <BottomNav />
    </div>
  );
}

export default Layout;
