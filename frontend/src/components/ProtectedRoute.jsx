import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.js';

// Route guard. While auth resolves, shows a terminal-style loader. Unauthenticated
// users are redirected to /verify (preserving where they were headed so we can
// bounce them back after login).

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg font-mono text-fg-muted">
        <span className="terminal-cursor">authenticating</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/verify" replace state={{ from: location.pathname }} />;
  }

  return children;
}
