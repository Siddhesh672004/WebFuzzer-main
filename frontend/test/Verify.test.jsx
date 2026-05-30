import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Mock the API client so the OTP flow is driven by us, not the network.
vi.mock('../src/api/client.js', () => ({
  authApi: {
    me: vi.fn(() => Promise.reject({ status: 401, code: 'NO_TOKEN' })),
    sendOtp: vi.fn(),
    verifyOtp: vi.fn(),
    logout: vi.fn(),
  },
  systemApi: { health: vi.fn() },
}));

import { authApi } from '../src/api/client.js';
import Verify from '../src/pages/Verify.jsx';

function renderVerify() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/verify']}>
        <Routes>
          <Route path="/verify" element={<Verify />} />
          <Route path="/dashboard" element={<div>DASHBOARD</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('Verify page OTP flow', () => {
  beforeEach(() => vi.clearAllMocks());

  it('validates the email before sending', async () => {
    const user = userEvent.setup();
    renderVerify();
    await user.type(screen.getByLabelText(/email/i), 'not-an-email');
    await user.click(screen.getByRole('button', { name: /send code/i }));
    expect(await screen.findByText(/valid email/i)).toBeInTheDocument();
    expect(authApi.sendOtp).not.toHaveBeenCalled();
  });

  it('advances to the OTP step after sending', async () => {
    authApi.sendOtp.mockResolvedValue({ devOtp: '123456' });
    const user = userEvent.setup();
    renderVerify();
    await user.type(screen.getByLabelText(/email/i), 'user@example.com');
    await user.click(screen.getByRole('button', { name: /send code/i }));

    expect(await screen.findByLabelText(/6-digit code/i)).toBeInTheDocument();
    expect(authApi.sendOtp).toHaveBeenCalledWith('user@example.com');
    // Dev hint surfaces the code locally.
    expect(screen.getByText('123456')).toBeInTheDocument();
  });

  it('verifies the code and navigates to the dashboard', async () => {
    authApi.sendOtp.mockResolvedValue({});
    authApi.verifyOtp.mockResolvedValue({ user: { id: '1', email: 'user@example.com' } });
    const user = userEvent.setup();
    renderVerify();

    await user.type(screen.getByLabelText(/email/i), 'user@example.com');
    await user.click(screen.getByRole('button', { name: /send code/i }));
    await user.type(await screen.findByLabelText(/6-digit code/i), '123456');
    await user.click(screen.getByRole('button', { name: /verify/i }));

    await waitFor(() => expect(screen.getByText('DASHBOARD')).toBeInTheDocument());
    expect(authApi.verifyOtp).toHaveBeenCalledWith('user@example.com', '123456');
  });

  it('shows attempts-left on a wrong code', async () => {
    authApi.sendOtp.mockResolvedValue({});
    authApi.verifyOtp.mockRejectedValue({ code: 'OTP_MISMATCH', details: { attemptsLeft: 2 } });
    const user = userEvent.setup();
    renderVerify();

    await user.type(screen.getByLabelText(/email/i), 'user@example.com');
    await user.click(screen.getByRole('button', { name: /send code/i }));
    await user.type(await screen.findByLabelText(/6-digit code/i), '000000');
    await user.click(screen.getByRole('button', { name: /verify/i }));

    expect(await screen.findByText(/2 attempts left/i)).toBeInTheDocument();
  });

  it('strips non-digits from the OTP input', async () => {
    authApi.sendOtp.mockResolvedValue({});
    const user = userEvent.setup();
    renderVerify();
    await user.type(screen.getByLabelText(/email/i), 'user@example.com');
    await user.click(screen.getByRole('button', { name: /send code/i }));

    const otpInput = await screen.findByLabelText(/6-digit code/i);
    await user.type(otpInput, 'a1b2c3d4e5');
    expect(otpInput).toHaveValue('12345');
  });
});
