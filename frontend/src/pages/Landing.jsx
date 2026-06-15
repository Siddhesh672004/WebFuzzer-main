import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import {
  Shield, Bug, FileSearch, Fingerprint, KeyRound, Braces, Network, Radar,
  GitCompareArrows, Gauge, Lock, Timer, ScrollText, EyeOff, ChevronRight, Terminal,
} from 'lucide-react';

// Landing — the public face of SmartFuzz. Pure phosphor-terminal identity:
// a typed scan replay as the hero visual (mirrors the real ScanMonitor output),
// the seven actual engine modules, real numbers from the codebase, and the
// safety engineering that makes an active scanner shippable. All motion is
// transform/opacity, ease-out, and collapses under prefers-reduced-motion.

const EASE = [0.23, 1, 0.32, 1];

/* ---------------------------------- motion ---------------------------------- */

function Reveal({ children, delay = 0, className = '', y = 16 }) {
  const reduce = useReducedMotion();
  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-70px' }}
      transition={{ duration: 0.5, delay, ease: EASE }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* Decrypt effect: glyphs settle left-to-right, once on mount. */
const GLYPHS = '!<>-_/[]{}=+*^?#01';
function Scramble({ text }) {
  const reduce = useReducedMotion();
  const [out, setOut] = useState(reduce ? text : '');
  useEffect(() => {
    if (reduce) return undefined;
    let frame = 0;
    const total = 26;
    const id = setInterval(() => {
      frame += 1;
      const settled = Math.floor((frame / total) * text.length);
      setOut(
        text
          .split('')
          .map((ch, i) => {
            if (ch === ' ' || i < settled) return ch;
            return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
          })
          .join(''),
      );
      if (frame >= total) {
        setOut(text);
        clearInterval(id);
      }
    }, 34);
    return () => clearInterval(id);
  }, [text, reduce]);
  return <span className="text-accent text-glow">{out || ' '}</span>;
}

/* ------------------------------- terminal demo ------------------------------ */

const CMD = 'smartfuzz scan https://staging.yourapp.dev --preset standard';
const DEMO_LINES = [
  { kind: 'ok', text: 'authorization confirmed · consent logged' },
  { kind: 'mod', mod: 'crawler', text: '47 endpoints · 12 forms · 9 js files' },
  { kind: 'mod', mod: 'passive', text: 'missing CSP · cookie without HttpOnly' },
  { kind: 'mod', mod: 'exposed', text: '/.git/HEAD responds 200 · soft-404 check passed' },
  { kind: 'mod', mod: 'fingerprint', text: 'nginx 1.18 · jQuery 3.4.1 · 2 known CVEs' },
  { kind: 'critical', mod: 'fuzzer', text: "sql injection @ /search?q= · ' OR 1=1-- · CVSS 9.8" },
  { kind: 'high', mod: 'fuzzer', text: 'reflected xss @ /comment?text= · CVSS 6.1' },
  { kind: 'medium', mod: 'auth', text: 'no rate limit on /login · 20 requests in 2.1s' },
  { kind: 'high', mod: 'secrets', text: 'AWS key in app.min.js:1402 · stored masked' },
  { kind: 'done', text: 'scan complete · 14 findings · security score 38/100' },
];
const LINE_CLS = {
  ok: 'text-accent',
  mod: 'text-fg-muted',
  critical: 'text-severity-critical',
  high: 'text-severity-high',
  medium: 'text-severity-medium',
  done: 'text-accent font-semibold',
};

function TerminalDemo() {
  const reduce = useReducedMotion();
  const [cmdChars, setCmdChars] = useState(reduce ? CMD.length : 0);
  const [lineCount, setLineCount] = useState(reduce ? DEMO_LINES.length : 0);
  const running = lineCount < DEMO_LINES.length;

  useEffect(() => {
    if (reduce) return undefined;
    let alive = true;
    let timer;
    function start() {
      if (!alive) return;
      setCmdChars(0);
      setLineCount(0);
      let c = 0;
      let l = 0;
      const revealLine = () => {
        if (!alive) return;
        l += 1;
        setLineCount(l);
        if (l < DEMO_LINES.length) timer = setTimeout(revealLine, 220 + Math.random() * 260);
        else timer = setTimeout(start, 6000); // hold the result, then replay
      };
      const typeCmd = () => {
        if (!alive) return;
        c += 1;
        setCmdChars(c);
        if (c < CMD.length) timer = setTimeout(typeCmd, 14 + Math.random() * 26);
        else timer = setTimeout(revealLine, 420);
      };
      typeCmd();
    }
    start();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [reduce]);

  return (
    <div className="card crt relative overflow-hidden bg-bg-inset shadow-panel">
      <div className="flex items-center gap-1.5 border-b border-border px-3 py-2">
        <span className="h-2.5 w-2.5 rounded-full bg-severity-critical/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-severity-medium/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-accent/70" />
        <span className="ml-2 font-mono text-[11px] text-fg-subtle">scan.log</span>
        <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[11px] text-fg-subtle">
          <span className={`h-1.5 w-1.5 rounded-full ${running ? 'animate-pulse bg-accent' : 'bg-accent-dim'}`} />
          {running ? 'scanning' : 'complete'}
        </span>
      </div>
      <div className="h-[330px] space-y-1.5 px-4 py-3 font-mono text-[12.5px] leading-relaxed sm:text-[13px]">
        <div className="text-fg">
          <span className="select-none text-accent">$ </span>
          {CMD.slice(0, cmdChars)}
          {cmdChars < CMD.length && <span className="terminal-cursor" />}
        </div>
        {DEMO_LINES.slice(0, lineCount).map((line, i) => (
          <div key={i} className="flex gap-2 whitespace-pre-wrap break-all animate-slide-up">
            <span className="select-none shrink-0 text-accent/60">{line.kind === 'ok' || line.kind === 'done' ? '✓' : '›'}</span>
            {line.mod && <span className="w-[11ch] shrink-0 text-accent-dim">{line.mod}</span>}
            <span className={LINE_CLS[line.kind]}>{line.text}</span>
          </div>
        ))}
        {lineCount >= DEMO_LINES.length && (
          <div className="text-fg">
            <span className="select-none text-accent">$ </span>
            <span className="terminal-cursor" />
          </div>
        )}
      </div>
    </div>
  );
}

/* ----------------------------------- data ----------------------------------- */

const STATS = [
  { value: '42', label: 'vulnerability types, each with a fix guide' },
  { value: '7', label: 'scan modules behind one rate limiter' },
  { value: '5', label: 'report formats, PDF to JSON' },
  { value: '$0', label: 'runtime cost, no cloud, no paid APIs' },
];

const MODULES = [
  {
    icon: Bug,
    name: 'payload fuzzer',
    desc: 'Classifies every parameter, fires curated payloads against a baseline, reads the response for proof, then mutates promising hits to slip past filters.',
    payloads: ["' OR 1=1--", '<script>alert(1)</script>', '{{7*7}}', '../../etc/passwd', '; sleep 5', '{"$ne": null}'],
    big: true,
  },
  { icon: Network, name: 'crawler', desc: 'Breadth-first discovery of same-host pages, forms, and script files, depth-capped and deduplicated.' },
  { icon: FileSearch, name: 'passive analyzer', desc: 'Reads headers and bodies it already has: CSP, HSTS, cookies, CORS, stack traces, leaked internals.' },
  { icon: Radar, name: 'exposed files', desc: 'Probes 200+ sensitive paths with soft-404 detection, so a server that answers 200 to everything cannot fake it out.' },
  { icon: Fingerprint, name: 'tech fingerprinter', desc: 'Detects frameworks and versions, then matches them against a local CVE database. No external lookups.' },
  { icon: KeyRound, name: 'auth tester', desc: 'Checks brute-force protection and default credentials. Intrusive probes stay behind an explicit aggressive-mode switch.' },
  {
    icon: Braces,
    name: 'js secret scanner',
    desc: 'Downloads every script the crawler saw and runs 38 secret patterns over the source. Only a masked preview is ever stored:',
    secret: 'AKIA3X9T************************',
    wide: true,
  },
];

const STEPS = [
  {
    title: 'Verify',
    desc: 'A six-digit code to your email, hashed in Redis, gone in ten minutes. No passwords exist anywhere in the system.',
  },
  {
    title: 'Scan',
    desc: 'Paste a target you are authorized to test and confirm it. Watch every module stream its work live over SSE: endpoints, payloads, findings as they land.',
  },
  {
    title: 'Fix and rescan',
    desc: 'Every finding ships with what went wrong, why it matters, and before/after code. Rescan and SmartFuzz proves whether the fix held.',
  },
];

const SAFETY = [
  {
    icon: Lock,
    title: 'SSRF guard on every request',
    desc: 'Each outbound URL is DNS-resolved and checked against private, loopback, and cloud-metadata ranges. Every redirect hop is re-checked.',
  },
  {
    icon: Gauge,
    title: 'One shared rate limiter',
    desc: 'A token bucket capped at 10 req/s spans all seven modules, so concurrency can never become a flood.',
  },
  {
    icon: ScrollText,
    title: 'Consent, logged',
    desc: 'No scan starts without an explicit authorization confirmation. User, IP, timestamp, and user-agent are recorded on the scan.',
  },
  {
    icon: EyeOff,
    title: 'Secrets stay masked',
    desc: 'A matched credential is stored as its first eight characters plus asterisks. The full value never touches the database.',
  },
  {
    icon: Timer,
    title: 'Hard resource caps',
    desc: 'Per-request timeouts, a 2 MB body cap, crawl depth ceilings, and a per-scan wall-clock budget.',
  },
  {
    icon: Terminal,
    title: 'Offline by design',
    desc: 'Detection runs against the target and bundled local data only. Tests never touch the live internet.',
  },
];

const COMPARE_CHIPS = [
  { label: 'FIXED', cls: 'border-accent/40 bg-accent/10 text-accent' },
  { label: 'PERSISTS', cls: 'border-severity-high/40 bg-severity-high/10 text-severity-high' },
  { label: 'NEW', cls: 'border-severity-low/40 bg-severity-low/10 text-severity-low' },
  { label: 'REGRESSED', cls: 'border-severity-critical/40 bg-severity-critical/10 text-severity-critical' },
];

/* --------------------------------- sections --------------------------------- */

function Nav() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/70 bg-bg/85 backdrop-blur">
      <nav className="mx-auto flex h-16 max-w-6xl items-center gap-8 px-4">
        <Link to="/" className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-accent" aria-hidden="true" />
          <span className="font-mono text-lg font-bold text-fg">
            Smart<span className="text-accent">Fuzz</span>
          </span>
        </Link>
        <div className="hidden gap-6 font-mono text-sm text-fg-muted md:flex">
          <a href="#engine" className="transition-colors duration-150 hover:text-accent">Engine</a>
          <a href="#how-it-works" className="transition-colors duration-150 hover:text-accent">How it works</a>
          <a href="#safety" className="transition-colors duration-150 hover:text-accent">Safety</a>
        </div>
        <Link to="/dashboard" className="btn-primary ml-auto px-4 py-2 font-mono text-sm">
          Launch console
        </Link>
      </nav>
    </header>
  );
}

function Hero() {
  return (
    <section className="grid-bg relative overflow-hidden">
      {/* Phosphor bloom behind the terminal. Decorative; drifts slowly. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute right-[-10%] top-[10%] h-[420px] w-[420px] animate-drift rounded-full bg-accent/10 blur-3xl"
      />
      <div className="mx-auto grid min-h-[calc(100dvh-4rem)] max-w-6xl items-center gap-12 px-4 py-16 lg:grid-cols-2 lg:gap-10">
        <div>
          <Reveal>
            <p className="mb-5 font-mono text-sm text-fg-muted">
              <span className="text-accent">$</span> zero-cost web vulnerability scanner, fully local
            </p>
          </Reveal>
          <Reveal delay={0.05}>
            <h1 className="text-4xl leading-[1.05] text-fg sm:text-5xl lg:text-6xl">
              Hack yourself before <Scramble text="they do." />
            </h1>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mt-6 max-w-[46ch] text-base leading-relaxed text-fg-muted sm:text-lg">
              SmartFuzz crawls your app, fires real payloads, scores every finding with CVSS 3.1,
              and hands you the exact fix.
            </p>
          </Reveal>
          <Reveal delay={0.15}>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Link to="/dashboard" className="btn-primary px-6 py-3 font-mono text-sm">
                Start scanning
                <ChevronRight className="h-4 w-4" aria-hidden="true" />
              </Link>
              <a href="#engine" className="btn-ghost px-6 py-3 font-mono text-sm">
                See the engine
              </a>
            </div>
          </Reveal>
        </div>
        <Reveal delay={0.2} y={24}>
          <TerminalDemo />
        </Reveal>
      </div>
    </section>
  );
}

function StatStrip() {
  return (
    <section className="border-y border-border bg-bg-subtle/60">
      <div className="mx-auto grid max-w-6xl grid-cols-2 divide-border sm:grid-cols-4 sm:divide-x">
        {STATS.map((s, i) => (
          <Reveal key={s.value} delay={i * 0.05} className="px-6 py-7">
            <div className="font-mono text-4xl font-bold text-accent">{s.value}</div>
            <div className="mt-1.5 text-sm leading-snug text-fg-muted">{s.label}</div>
          </Reveal>
        ))}
      </div>
    </section>
  );
}

function ModuleCell({ mod, delay }) {
  const { icon: Icon } = mod;
  return (
    <Reveal
      delay={delay}
      className={`card group relative overflow-hidden p-6 transition-colors duration-200 hover:border-accent/40 ${
        mod.big ? 'flex flex-col sm:col-span-2 lg:col-span-4 lg:row-span-2' : mod.wide ? 'sm:col-span-2 lg:col-span-6' : 'lg:col-span-2'
      }`}
    >
      {mod.big && (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-24 animate-scan-line bg-gradient-to-b from-accent/10 to-transparent"
        />
      )}
      <Icon className="mb-4 h-5 w-5 text-accent" aria-hidden="true" />
      <h3 className="font-mono text-base font-semibold text-fg">{mod.name}</h3>
      <p className="mt-2 max-w-[52ch] text-sm leading-relaxed text-fg-muted">{mod.desc}</p>
      {mod.payloads && (
        <div className="mt-auto pt-6">
          <p className="mb-2.5 font-mono text-xs text-fg-subtle">live from the curated payload set:</p>
          <div className="flex flex-wrap gap-2">
            {mod.payloads.map((p) => (
              <code key={p} className="chip border border-border bg-bg-inset text-fg-muted transition-colors duration-150 group-hover:border-accent/30">
                {p}
              </code>
            ))}
          </div>
        </div>
      )}
      {mod.secret && (
        <code className="mt-4 block w-fit rounded-md border border-severity-high/30 bg-bg-inset px-3 py-1.5 font-mono text-xs text-severity-high">
          {mod.secret}
        </code>
      )}
    </Reveal>
  );
}

function Modules() {
  return (
    <section id="engine" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-24">
      <Reveal>
        <h2 className="max-w-[22ch] text-3xl text-fg sm:text-4xl">
          Seven modules. One rate limiter. Real proof.
        </h2>
        <p className="mt-3 max-w-[58ch] text-fg-muted">
          Nothing is flagged on a hunch: findings need evidence in the response, and soft-404
          control checks keep the noise out.
        </p>
      </Reveal>
      <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
        {MODULES.map((m, i) => (
          <ModuleCell key={m.name} mod={m} delay={Math.min(i * 0.05, 0.25)} />
        ))}
      </div>
    </section>
  );
}

function HowItWorks() {
  return (
    <section id="how-it-works" className="border-t border-border bg-bg-subtle/40">
      <div className="mx-auto max-w-6xl scroll-mt-20 px-4 py-24">
        <Reveal>
          <h2 className="text-3xl text-fg sm:text-4xl">From URL to fixed in three moves.</h2>
        </Reveal>
        <div className="mt-12 space-y-0">
          {STEPS.map((step, i) => (
            <Reveal key={step.title} delay={i * 0.06}>
              <div className="group relative flex gap-6 border-l border-border pb-16 pl-8 last:pb-0 sm:gap-10 sm:pl-12">
                <span
                  aria-hidden="true"
                  className="absolute -left-[5px] top-1 h-2.5 w-2.5 rounded-full bg-accent transition-transform duration-200 ease-out group-hover:scale-125"
                />
                <span className="hidden w-20 shrink-0 pt-0.5 font-mono text-sm text-fg-subtle sm:block">0{i + 1}</span>
                <div>
                  <h3 className="text-xl text-fg sm:text-2xl">{step.title}</h3>
                  <p className="mt-2 max-w-[60ch] leading-relaxed text-fg-muted">{step.desc}</p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

function Scoring() {
  return (
    <section className="mx-auto grid max-w-6xl items-center gap-12 px-4 py-24 lg:grid-cols-2">
      <Reveal>
        <h2 className="max-w-[20ch] text-3xl text-fg sm:text-4xl">Scored, not just found.</h2>
        <p className="mt-4 max-w-[56ch] leading-relaxed text-fg-muted">
          Every finding gets a CVSS 3.1 base score computed with the FIRST.org integer roundup,
          the same arithmetic NVD uses. Severity counts roll up into a 0-100 security score, and
          each vulnerability links to a fix guide with before and after code.
        </p>
        <p className="mt-3 font-mono text-sm text-fg-subtle">
          critical -20 · high -10 · medium -5 · low -2
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="space-y-2.5">
          {[
            { cls: 'border-severity-critical/30 bg-severity-critical/10 text-severity-critical', sev: 'critical', score: '9.8', label: 'SQL injection', loc: '/search?q=' },
            { cls: 'border-severity-high/30 bg-severity-high/10 text-severity-high', sev: 'high', score: '7.5', label: 'Exposed .git directory', loc: '/.git/HEAD' },
            { cls: 'border-severity-medium/30 bg-severity-medium/10 text-severity-medium', sev: 'medium', score: '6.1', label: 'Reflected XSS', loc: '/comment?text=' },
          ].map((f) => (
            <div key={f.label} className="card flex items-center gap-3 p-4 shadow-panel">
              <span className={`chip border font-semibold uppercase ${f.cls}`}>
                {f.sev} {f.score}
              </span>
              <div className="min-w-0">
                <p className="truncate font-mono text-sm text-fg">{f.label}</p>
                <p className="truncate font-mono text-xs text-fg-subtle">{f.loc}</p>
              </div>
              <ChevronRight className="ml-auto h-4 w-4 shrink-0 text-fg-subtle" aria-hidden="true" />
            </div>
          ))}
          <div className="card flex items-center justify-between p-4 shadow-panel">
            <span className="font-mono text-sm text-fg-muted">security score</span>
            <span className="font-mono text-2xl font-bold text-severity-high">38<span className="text-sm text-fg-subtle">/100</span></span>
          </div>
        </div>
      </Reveal>
    </section>
  );
}

function CompareSection() {
  return (
    <section className="border-t border-border">
      <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 py-24 lg:grid-cols-2">
        <Reveal className="lg:order-2">
          <h2 className="max-w-[20ch] text-3xl text-fg sm:text-4xl">Prove the fix held.</h2>
          <p className="mt-4 max-w-[56ch] leading-relaxed text-fg-muted">
            Every finding carries a stable signature: the vulnerability type, the normalized path,
            and the parameter. Rescan the same target and SmartFuzz diffs the two sets, labels
            every finding, and charts your score over time.
          </p>
        </Reveal>
        <Reveal delay={0.1} className="lg:order-1">
          <div className="card p-6 shadow-panel">
            <div className="flex flex-wrap gap-2">
              {COMPARE_CHIPS.map((c) => (
                <span key={c.label} className={`chip border font-semibold ${c.cls}`}>{c.label}</span>
              ))}
            </div>
            <svg viewBox="0 0 360 120" className="mt-6 w-full" role="img" aria-label="Security score trend rising from 38 to 92 across three scans">
              <polyline
                points="10,96 180,62 350,28"
                fill="none"
                stroke="#2FD06F"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {[
                { x: 10, y: 96, v: 38 },
                { x: 180, y: 62, v: 61 },
                { x: 350, y: 28, v: 92 },
              ].map((p) => (
                <g key={p.v}>
                  <circle cx={p.x} cy={p.y} r="4" fill="#0B100D" stroke="#2FD06F" strokeWidth="2.5" />
                  <text x={Math.min(Math.max(p.x, 16), 336)} y={p.y - 12} textAnchor="middle" fill="#94A89A" fontFamily="JetBrains Mono, monospace" fontSize="12">
                    {p.v}
                  </text>
                </g>
              ))}
            </svg>
            <p className="mt-2 font-mono text-xs text-fg-subtle">score across three scans of the same target</p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function Safety() {
  return (
    <section id="safety" className="border-t border-border bg-bg-inset/60">
      <div className="mx-auto max-w-6xl scroll-mt-20 px-4 py-24">
        <Reveal>
          <h2 className="max-w-[24ch] text-3xl text-fg sm:text-4xl">An active scanner you can trust running.</h2>
          <p className="mt-3 max-w-[58ch] text-fg-muted">
            Firing payloads at a live system is a responsibility. These guardrails are not options,
            they are the architecture.
          </p>
        </Reveal>
        <div className="mt-12 grid gap-x-12 gap-y-10 sm:grid-cols-2 lg:grid-cols-3">
          {SAFETY.map((item, i) => (
            <Reveal key={item.title} delay={Math.min(i * 0.05, 0.25)}>
              <div className="flex gap-4">
                <item.icon className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden="true" />
                <div>
                  <h3 className="font-mono text-sm font-semibold text-fg">{item.title}</h3>
                  <p className="mt-1.5 text-sm leading-relaxed text-fg-muted">{item.desc}</p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

function FinalCta() {
  return (
    <section className="border-t border-border">
      <div className="mx-auto max-w-3xl px-4 py-28 text-center">
        <Reveal>
          <p className="font-mono text-sm text-fg-muted">
            <span className="text-accent">$</span> smartfuzz scan https://something-you-own.dev
            <span className="terminal-cursor" />
          </p>
          <h2 className="mt-5 text-3xl text-fg sm:text-5xl">Point it at something you own.</h2>
          <div className="mt-9 flex justify-center">
            <Link to="/dashboard" className="btn-primary px-8 py-3.5 font-mono text-sm">
              Start scanning
              <ChevronRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </div>
          <p className="mx-auto mt-7 max-w-[52ch] text-sm text-fg-subtle">
            SmartFuzz is an active scanner. Only scan systems you own or have explicit written
            permission to test. Practice safely on DVWA, WebGoat, or Juice Shop.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-border bg-bg-subtle/50">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-10 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-accent" aria-hidden="true" />
          <span className="font-mono text-sm font-bold text-fg">
            Smart<span className="text-accent">Fuzz</span>
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-6 font-mono text-xs text-fg-muted">
          <a href="#engine" className="transition-colors duration-150 hover:text-accent">Engine</a>
          <a href="#how-it-works" className="transition-colors duration-150 hover:text-accent">How it works</a>
          <a href="#safety" className="transition-colors duration-150 hover:text-accent">Safety</a>
          <Link to="/verify" className="transition-colors duration-150 hover:text-accent">Sign in</Link>
        </div>
      </div>
    </footer>
  );
}

export default function Landing() {
  return (
    <div className="min-h-screen bg-bg">
      <Nav />
      <main>
        <Hero />
        <StatStrip />
        <Modules />
        <HowItWorks />
        <Scoring />
        <CompareSection />
        <Safety />
        <FinalCta />
      </main>
      <Footer />
    </div>
  );
}
