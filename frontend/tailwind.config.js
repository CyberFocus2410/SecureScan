/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          critical: '#B42318',
          high: '#C2410C',
          medium: '#A16207',
          low: '#1D4ED8',
          info: '#475569',
          ok: '#15803D',
          unknown: '#6B21A8'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace']
      }
    },
  },
  plugins: [],
}

