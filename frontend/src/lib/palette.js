// Hex mirror of the Phosphor theme tokens (tailwind.config.js) for libraries
// that need literal colors (recharts strokes, inline SVG). Keep in sync with
// the OKLCH tokens — these are their sRGB equivalents.

export const PALETTE = {
  accent: '#2FD06F',
  accentDim: '#1F9D52',
  bg: '#0B100D',
  bgInset: '#070B08',
  border: '#26352C',
  fg: '#DCE8DE',
  fgMuted: '#94A89A',
  fgSubtle: '#677868',
};

// Severity bands — mirrors shared/severity + the Tailwind `severity.*` tokens.
export const SEVERITY_HEX = {
  critical: '#E9554A',
  high: '#E68A4B',
  medium: '#D9C24B',
  low: '#5C9CEF',
  informational: '#8C97A0',
  info: '#8C97A0',
};

// Scan lifecycle states. Running pulses phosphor; completed settles dim green.
export const STATUS_HEX = {
  pending: '#8C97A0',
  running: '#2FD06F',
  completed: '#1F9D52',
  failed: '#E9554A',
  cancelled: '#8C97A0',
};
