import { useState, useRef, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Mail, KeyRound, ArrowLeft } from 'lucide-react';
import { useSendOtp, useVerifyOtp } from '../hooks/useAuth.js';
import { Button, Input, Alert } from '../components/ui.jsx';

// Verify page (PRD §4) — the only auth surface. Two steps:
//   1. enter email → request OTP
//   2. enter the 6-digit code → verify → JWT cookie set → redirect to dashboard
// No passwords anywhere. In dev the API returns a preview URL / devOtp, which
// we surface to make local testing frictionless.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function Verify() {
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = location.state?.from || '/dashboard';

  const [step, setStep] = useState('email'); // 'email' | 'otp'
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [formError, setFormError] = useState('');
  const [devHint, setDevHint] = useState(null); // { previewUrl?, devOtp? }
  const otpRef = useRef(null);

  const sendOtp = useSendOtp();
  const verifyOtp = useVerifyOtp();

  useEffect(() => {
    if (step === 'otp') otpRef.current?.focus();
  }, [step]);

  async function handleSendOtp(e) {
    e.preventDefault();
    setFormError('');
    if (!EMAIL_RE.test(email)) {
      setFormError('Enter a valid email address.');
      return;
    }
    try {
      const res = await sendOtp.mutateAsync(email.trim().toLowerCase());
      setDevHint({ previewUrl: res.previewUrl, devOtp: res.devOtp });
      setStep('otp');
    } catch (err) {
      if (err.code === 'OTP_COOLDOWN') {
        setFormError(`Please wait ${err.details?.retryAfterSeconds ?? 60}s before requesting another code.`);
      } else {
        setFormError(err.message || 'Could not send code. Try again.');
      }
    }
  }

  async function handleVerify(e) {
    e.preventDefault();
    setFormError('');
    if (!/^\d{6}$/.test(otp)) {
      setFormError('Enter the 6-digit code.');
      return;
    }
    try {
      await verifyOtp.mutateAsync({ email: email.trim().toLowerCase(), otp });
      navigate(redirectTo, { replace: true });
    } catch (err) {
      if (err.code === 'OTP_MISMATCH') {
        const left = err.details?.attemptsLeft;
        setFormError(`Incorrect code.${typeof left === 'number' ? ` ${left} attempt${left === 1 ? '' : 's'} left.` : ''}`);
      } else if (err.code === 'OTP_ATTEMPTS_EXCEEDED' || err.code === 'OTP_NOT_FOUND') {
        setFormError('Code expired or too many attempts. Request a new one.');
        setStep('email');
        setOtp('');
      } else {
        setFormError(err.message || 'Verification failed.');
      }
    }
  }

  return (
    <main className="grid-bg flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="card w-full max-w-md p-8 shadow-panel animate-scale-in">
        <div className="mb-6 flex items-center gap-3">
          <Shield className="h-8 w-8 text-accent" aria-hidden="true" />
          <h1 className="font-mono text-2xl font-bold text-fg">
            Smart<span className="text-accent">Fuzz</span>
          </h1>
        </div>

        <p className="mb-6 font-mono text-sm text-fg-muted">
          <span className="text-accent">$</span>{' '}
          {step === 'email' ? 'verify your email to begin' : `code sent to ${email}`}
          <span className="terminal-cursor" />
        </p>

        {formError && (
          <div className="mb-4">
            <Alert variant="error">{formError}</Alert>
          </div>
        )}

        {devHint && (devHint.previewUrl || devHint.devOtp) && (
          <div className="mb-4">
            <Alert variant="info">
              <span className="font-bold">dev:</span>{' '}
              {devHint.devOtp ? (
                <>
                  code is <span className="font-bold">{devHint.devOtp}</span>
                </>
              ) : (
                <a href={devHint.previewUrl} target="_blank" rel="noreferrer" className="underline">
                  open email preview
                </a>
              )}
            </Alert>
          </div>
        )}

        {step === 'email' ? (
          <form onSubmit={handleSendOtp} className="space-y-4" noValidate>
            <Input
              id="email"
              type="email"
              label="Email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              autoFocus
            />
            <Button type="submit" loading={sendOtp.isPending} className="w-full">
              <Mail className="h-4 w-4" aria-hidden="true" />
              Send code
            </Button>
          </form>
        ) : (
          <form onSubmit={handleVerify} className="space-y-4" noValidate>
            <Input
              id="otp"
              ref={otpRef}
              inputMode="numeric"
              maxLength={6}
              label="6-digit code"
              placeholder="••••••"
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="text-center text-2xl tracking-[0.5em]"
              autoComplete="one-time-code"
            />
            <Button type="submit" loading={verifyOtp.isPending} className="w-full">
              <KeyRound className="h-4 w-4" aria-hidden="true" />
              Verify
            </Button>
            <div className="flex items-center justify-between font-mono text-xs">
              <button
                type="button"
                onClick={() => {
                  setStep('email');
                  setOtp('');
                  setFormError('');
                }}
                className="inline-flex items-center gap-1 text-fg-muted hover:text-fg"
              >
                <ArrowLeft className="h-3 w-3" aria-hidden="true" />
                change email
              </button>
              <button
                type="button"
                onClick={handleSendOtp}
                disabled={sendOtp.isPending}
                className="text-accent hover:underline disabled:opacity-50"
              >
                resend code
              </button>
            </div>
          </form>
        )}

        <p className="mt-6 border-t border-border-muted pt-4 font-mono text-xs text-fg-subtle">
          No passwords. We only store your email to send the code.
        </p>
      </div>
    </main>
  );
}
