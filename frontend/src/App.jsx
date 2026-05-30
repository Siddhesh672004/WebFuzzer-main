import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute.jsx';

const Verify = lazy(() => import('./pages/Verify.jsx'));
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'));
const NewScan = lazy(() => import('./pages/NewScan.jsx'));
const ScanMonitor = lazy(() => import('./pages/ScanMonitor.jsx'));
const ScanResults = lazy(() => import('./pages/ScanResults.jsx'));
const Comparison = lazy(() => import('./pages/Comparison.jsx'));
const Reports = lazy(() => import('./pages/Reports.jsx'));

function PageFallback() {
  return (
    <div className="flex h-screen items-center justify-center text-fg-muted font-mono">
      <span className="terminal-cursor">loading</span>
    </div>
  );
}

function Protected({ children }) {
  return <ProtectedRoute>{children}</ProtectedRoute>;
}

export default function App() {
  return (
    <Suspense fallback={<PageFallback />}>
      <Routes>
        <Route path="/verify" element={<Verify />} />
        <Route path="/dashboard" element={<Protected><Dashboard /></Protected>} />
        <Route path="/scan/new" element={<Protected><NewScan /></Protected>} />
        <Route path="/scan/:id" element={<Protected><ScanMonitor /></Protected>} />
        <Route path="/results/:id" element={<Protected><ScanResults /></Protected>} />
        <Route path="/compare/:domain" element={<Protected><Comparison /></Protected>} />
        <Route path="/reports" element={<Protected><Reports /></Protected>} />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Suspense>
  );
}
