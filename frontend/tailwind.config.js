/** @type {import('tailwindcss').Config} */
// Hacker-themed dark terminal aesthetic (PRD §17). Severity colors mirror the
// CVSS bands defined once in @smartfuzz/shared/severity so UI and data agree.
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Base surfaces — GitHub-dark-inspired, deep terminal blacks.
        bg: {
          DEFAULT: '#0D1117',
          subtle: '#161B22',
          inset: '#010409',
        },
        border: {
          DEFAULT: '#30363D',
          muted: '#21262D',
        },
        fg: {
          DEFAULT: '#C9D1D9',
          muted: '#8B949E',
          subtle: '#6E7681',
        },
        // Accent — terminal green.
        accent: {
          DEFAULT: '#3FB950',
          dim: '#238636',
          glow: '#2EA043',
        },
        // Severity palette (matches shared/severity SEVERITY_BANDS).
        severity: {
          critical: '#F85149',
          high: '#F78166',
          medium: '#D29922',
          low: '#58A6FF',
          info: '#8B949E',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      keyframes: {
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0' } },
        'pulse-glow': {
          '0%,100%': { boxShadow: '0 0 0 0 rgba(63,185,80,0.4)' },
          '50%': { boxShadow: '0 0 0 6px rgba(63,185,80,0)' },
        },
      },
      animation: {
        blink: 'blink 1s step-end infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
