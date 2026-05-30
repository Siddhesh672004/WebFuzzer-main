import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Suspense } from 'react';
import App from '../src/App.jsx';

// Mock the API client so auth state is deterministic in tests (no real network).
// authApi.me rejecting === unauthenticated.
vi.mock('../src/api/client.js', () => ({
  authApi: {
    me: vi.fn(() => Promise.reject({ status: 401, message: 'Unauthorized', code: 'NO_TOKEN' })),
    sendOtp: vi.fn(),
    verifyOtp: vi.fn(),
    logout: vi.fn(),
  },
  systemApi: { health: vi.fn() },
}));

function renderApp(initialPath = '/verify') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Suspense fallback={<div>loading</div>}>
          <App />
        </Suspense>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('App shell', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the SmartFuzz Verify page at /verify', async () => {
    renderApp('/verify');
    const heading = await screen.findByRole('heading', { level: 1 });
    expect(heading).toHaveTextContent(/smartfuzz/i);
  });

  it('shows the email step on the Verify page', async () => {
    renderApp('/verify');
    expect(await screen.findByText(/verify your email to begin/i)).toBeInTheDocument();
    expect(await screen.findByLabelText(/email/i)).toBeInTheDocument();
  });

  it('redirects an unauthenticated user from a protected route to /verify', async () => {
    renderApp('/dashboard');
    // ProtectedRoute resolves auth → unauthenticated → <Navigate to="/verify">.
    expect(await screen.findByText(/verify your email to begin/i)).toBeInTheDocument();
  });
});
