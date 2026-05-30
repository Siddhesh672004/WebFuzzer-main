import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Suspense } from 'react';
import App from '../src/App.jsx';

// Smoke test for the frontend shell: the app renders, lazy routing resolves to
// the Verify page, and an unknown path redirects to /verify. Proves the build
// graph (router + query + lazy + Tailwind classes) is wired correctly.

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
  it('renders the SmartFuzz Verify page at /verify', async () => {
    renderApp('/verify');
    // The brand splits "Smart" and "Fuzz" across nodes, so match on the
    // heading's combined text content rather than its accessible name.
    const heading = await screen.findByRole('heading', { level: 1 });
    expect(heading).toHaveTextContent(/smartfuzz/i);
  });

  it('redirects an unknown path to /verify', async () => {
    renderApp('/some/random/path');
    // The catch-all <Navigate> sends us to Verify.
    expect(await screen.findByText(/zero-cost web vulnerability scanner/i)).toBeInTheDocument();
  });
});
