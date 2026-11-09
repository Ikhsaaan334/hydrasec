import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../auth.jsx';
import { api } from '../api.js';

const ShieldIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

const USERNAME_HINT = '3-24 characters: lowercase letters, numbers, dots, dashes, underscores.';

export default function Login() {
  const { user, login, completeRegistration, requestOtp } = useAuth();
  const navigate = useNavigate();
  const [step, setStep] = useState(1); // 1=email, 2=kode OTP, 3=username (registrasi baru)
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [username, setUsername] = useState('');
  const [regToken, setRegToken] = useState('');
  const [usernameHint, setUsernameHint] = useState('');
  const [hint, setHint] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (user) navigate('/', { replace: true });
  }, [user, navigate]);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const t = setInterval(() => setCooldown((c) => Math.max(0, c - 1)), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  async function submitEmail(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const r = await requestOtp(email.trim());
      setHint(r.hint ?? 'Your code has been sent.');
      setCooldown(r.cooldownSeconds ?? 60);
      setStep(2);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await login(email.trim(), code.trim());
      if (data.pending) {
        setRegToken(data.regToken);
        setStep(3);
      }
      // email terdaftar: token tersimpan oleh AuthContext → redirect otomatis
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function submitUsername(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await completeRegistration(username.trim(), regToken);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function checkAvailability() {
    if (!username.trim()) return;
    try {
      const r = await api('/auth/username-available?u=' + encodeURIComponent(username.trim()));
      setUsernameHint(r.available ? `"${username.trim()}" is available ✓` : (r.reason ?? 'Not available'));
    } catch {
      setUsernameHint('');
    }
  }

  return (
    <div className="login-shell">
      <section className="login-hero" aria-label="About HydraSec">
        <div className="brandline">
          <ShieldIcon />
          <span style={{ fontWeight: 700, fontSize: 16 }}>HydraSec</span>
        </div>
        <h1 className="enter-rise">Security scanning orchestration, one interface.</h1>
        <p className="hero-sub enter-rise-2">
          Six penetration testing tools run as sandboxed ephemeral containers — queued,
          streamed live to your terminal, and normalized into a single findings schema.
        </p>
        <div className="hero-facts">
          <div className="hero-fact">
            <div className="n">6</div>
            <div className="l">orchestrated tools</div>
          </div>
          <div className="hero-fact">
            <div className="n">×2</div>
            <div className="l">worker concurrency</div>
          </div>
          <div className="hero-fact">
            <div className="n">100%</div>
            <div className="l">ephemeral containers</div>
          </div>
        </div>
      </section>

      <section className="login-panel">
        <div className="login-card">
          <h2>
            {step === 1 ? 'Sign in or register'
              : step === 2 ? 'Enter the code'
              : 'Pick your username'}
          </h2>
          <div className="login-steps" aria-hidden="true">
            <span className={'dot' + (step >= 1 ? ' on' : '')} />
            <span className={'dot' + (step >= 2 ? ' on' : '')} />
            <span className={'dot' + (step >= 3 ? ' on' : '')} />
          </div>

          {step === 1 && (
            <form onSubmit={submitEmail}>
              <div className="field">
                <label htmlFor="email">Email</label>
                <input
                  id="email"
                  className="input"
                  type="email"
                  required
                  autoComplete="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
                <p className="field-hint">
                  No passwords. We send a one-time code every time you sign in —
                  new accounts finish registration by picking a unique username.
                </p>
              </div>
              {error && <p className="field-error">{error}</p>}
              <button type="submit" className="btn btn-primary mt-16" disabled={busy || !email} style={{ width: '100%' }}>
                {busy ? <span className="spinner" /> : 'Send code'}
              </button>
            </form>
          )}

          {step === 2 && (
            <form onSubmit={submitCode}>
              <div className="field">
                <label htmlFor="code">6-digit code</label>
                <input
                  id="code"
                  className="input"
                  inputMode="numeric"
                  pattern="\d{6}"
                  maxLength={6}
                  required
                  autoFocus
                  placeholder="••••••"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  style={{ letterSpacing: '.5em', textAlign: 'center', fontSize: 20 }}
                />
              </div>
              {hint && <p className="field-hint">{hint}</p>}
              {error && <p className="field-error">{error}</p>}
              <button type="submit" className="btn btn-primary mt-16" disabled={busy || code.length !== 6} style={{ width: '100%' }}>
                {busy ? <span className="spinner" /> : 'Verify code'}
              </button>
              <button
                type="button"
                className="btn btn-ghost mt-8"
                style={{ width: '100%' }}
                disabled={busy || cooldown > 0}
                onClick={submitEmail}
              >
                {cooldown > 0 ? 'Resend code (' + cooldown + ' s)' : 'Resend code'}
              </button>
              <p className="field-hint mt-8" style={{ textAlign: 'center' }}>
                Local MailPit inbox: <a href="http://localhost:8025" target="_blank" rel="noreferrer">localhost:8025</a>
              </p>
            </form>
          )}

          {step === 3 && (
            <form onSubmit={submitUsername}>
              <p className="field-hint" style={{ marginTop: 0 }}>
                First time here! Pick a unique username — it identifies you on the
                scanning leaderboard instead of your email.
              </p>
              <div className="field mt-16">
                <label htmlFor="username">Username</label>
                <input
                  id="username"
                  className="input"
                  required
                  autoFocus
                  minLength={3}
                  maxLength={24}
                  placeholder="e.g. budi_sec"
                  value={username}
                  onChange={(e) => { setUsername(e.target.value.toLowerCase()); setUsernameHint(''); }}
                  onBlur={checkAvailability}
                />
                {usernameHint && <p className="field-hint">{usernameHint}</p>}
                <p className="field-hint">{USERNAME_HINT}</p>
              </div>
              {error && <p className="field-error">{error}</p>}
              <button type="submit" className="btn btn-primary mt-16" disabled={busy || username.trim().length < 3} style={{ width: '100%' }}>
                {busy ? <span className="spinner" /> : 'Finish registration'}
              </button>
            </form>
          )}
        </div>
      </section>
    </div>
  );
}
