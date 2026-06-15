/** @type {import('tailwindcss').Config} */
// "Phosphor" — the SmartFuzz hacker identity. Green-tinted terminal blacks on
// a perceptually-uniform OKLCH scale with a single phosphor-green accent.
// Severity colours stay semantic (risk earns colour) and mirror the CVSS bands
// in @smartfuzz/shared/severity. Charts use the hex mirror in src/lib/palette.js.
//
// Motion follows design-engineering rules: UI animations stay under 300ms on
// custom ease-out curves, animate only transform/opacity, and entrances start
// at scale(0.95)+ — never scale(0).
//
// Colours use the `/ <alpha-value>` form so Tailwind opacity modifiers
// (bg-accent/10, border-severity-critical/40, …) keep working with OKLCH.
const oklch = (l, c, h) => `oklch(${l} ${c} ${h} / <alpha-value>)`;

export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Terminal blacks, tinted toward green — never flat #000.
        bg: {
          DEFAULT: oklch(0.165, 0.014, 152),
          subtle: oklch(0.2, 0.016, 152),
          inset: oklch(0.13, 0.012, 152),
        },
        border: {
          DEFAULT: oklch(0.32, 0.022, 152),
          muted: oklch(0.245, 0.018, 152),
        },
        fg: {
          DEFAULT: oklch(0.93, 0.012, 145),
          muted: oklch(0.71, 0.02, 148),
          subtle: oklch(0.55, 0.022, 150),
        },
        // The one accent: phosphor green. Brand, primary action, focus, live state.
        accent: {
          DEFAULT: oklch(0.76, 0.17, 150),
          dim: oklch(0.6, 0.13, 150),
          glow: oklch(0.85, 0.2, 149),
        },
        // Severity — distinct from the accent so risk reads instantly.
        severity: {
          critical: oklch(0.62, 0.21, 25),
          high: oklch(0.7, 0.17, 45),
          medium: oklch(0.8, 0.14, 95),
          low: oklch(0.7, 0.12, 240),
          info: oklch(0.65, 0.02, 250),
        },
      },
      fontFamily: {
        display: ['"Space Grotesk"', '"Geist"', 'system-ui', 'sans-serif'],
        sans: ['"Geist"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      letterSpacing: {
        tightest: '-0.04em',
      },
      transitionTimingFunction: {
        // Punchy exponential ease-out — entrances and hovers.
        out: 'cubic-bezier(0.23, 1, 0.32, 1)',
        // Strong in-out — on-screen movement and morphs.
        'in-out': 'cubic-bezier(0.77, 0, 0.175, 1)',
        // Sheet/drawer settle.
        drawer: 'cubic-bezier(0.32, 0.72, 0, 1)',
      },
      boxShadow: {
        // Low neutral elevation for panels.
        panel: '0 1px 0 0 oklch(0.45 0.02 150 / 0.05), 0 8px 24px -12px oklch(0 0 0 / 0.6)',
        // Phosphor halo — brand moments only (primary CTA, selected preset).
        glow: '0 0 0 1px oklch(0.76 0.17 150 / 0.4), 0 0 24px -6px oklch(0.76 0.17 150 / 0.5)',
      },
      keyframes: {
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0' } },
        'pulse-glow': {
          '0%,100%': { boxShadow: '0 0 0 0 oklch(0.76 0.17 150 / 0.45)' },
          '50%': { boxShadow: '0 0 0 6px oklch(0.76 0.17 150 / 0)' },
        },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'scale-in': {
          from: { opacity: '0', transform: 'scale(0.95)' },
          to: { opacity: '1', transform: 'scale(1)' },
        },
        'scan-line': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(400%)' },
        },
        // Radar sweep for "scanning" state (conic highlight rotating).
        sweep: {
          from: { transform: 'rotate(0deg)' },
          to: { transform: 'rotate(360deg)' },
        },
        shake: {
          '0%,100%': { transform: 'translateX(0)' },
          '20%,60%': { transform: 'translateX(-6px)' },
          '40%,80%': { transform: 'translateX(6px)' },
        },
        // Landing hero: slow drifting glow. Decorative, gated by reduced-motion.
        drift: {
          '0%,100%': { transform: 'translate3d(0, 0, 0)' },
          '50%': { transform: 'translate3d(0, -18px, 0)' },
        },
      },
      animation: {
        blink: 'blink 1.1s step-end infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'slide-up': 'slide-up 0.24s cubic-bezier(0.23, 1, 0.32, 1)',
        'fade-in': 'fade-in 0.2s cubic-bezier(0.23, 1, 0.32, 1)',
        'scale-in': 'scale-in 0.2s cubic-bezier(0.23, 1, 0.32, 1)',
        'scan-line': 'scan-line 2.5s linear infinite',
        sweep: 'sweep 3.5s linear infinite',
        shake: 'shake 0.4s ease-in-out',
        drift: 'drift 9s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
