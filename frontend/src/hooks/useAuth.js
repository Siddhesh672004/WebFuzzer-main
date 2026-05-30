import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi } from '../api/client.js';

// Auth state via React Query. The current user is derived from GET /api/auth/me
// (the httpOnly cookie authenticates the request). Mutations for the OTP flow
// invalidate the user query so the app reacts to login/logout immediately.

const ME_KEY = ['auth', 'me'];

/** Current authenticated user, or null. `isLoading` while first resolving. */
export function useAuth() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ME_KEY,
    queryFn: () => authApi.me(),
    retry: false,
    staleTime: 60_000,
    // A 401 is expected when logged out — don't treat it as a hard error spam.
    select: (res) => res.user,
  });

  return {
    user: isError ? null : data ?? null,
    isLoading,
    isAuthenticated: !!data && !isError,
  };
}

/** Request an OTP for an email. */
export function useSendOtp() {
  return useMutation({
    mutationFn: (email) => authApi.sendOtp(email),
  });
}

/** Verify an OTP; on success the user query is refreshed. */
export function useVerifyOtp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ email, otp }) => authApi.verifyOtp(email, otp),
    onSuccess: (data) => {
      // Prime the cache so the redirect lands authenticated without a refetch.
      qc.setQueryData(ME_KEY, { user: data.user });
    },
  });
}

/** Log out and clear cached auth state. */
export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => authApi.logout(),
    onSuccess: () => {
      qc.setQueryData(ME_KEY, null);
      qc.invalidateQueries({ queryKey: ME_KEY });
    },
  });
}
