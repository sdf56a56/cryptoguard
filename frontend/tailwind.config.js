/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // 浅色「加密账本」主题
        paper: '#faf9f6',
        surface: '#ffffff',
        ink: {
          DEFAULT: '#182235',   // 主文字（深墨蓝）
          soft: '#4b5568',      // 次级文字
          faint: '#8b92a5',     // 弱文字
        },
        line: {
          DEFAULT: '#e6e2da',   // 暖灰描边
          strong: '#cfc9be',
        },
        vault: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          500: '#4361ee',       // 主色：信号蓝
          600: '#3451d1',
          700: '#2840a8',
          800: '#1f3280',
        },
        ok: {
          DEFAULT: '#0ca678',
          soft: '#e3f8f1',
        },
        bad: {
          DEFAULT: '#e03131',
          soft: '#fdeaea',
        },
        warn: {
          DEFAULT: '#e8890c',
          soft: '#fdf1de',
        },
        crypto: {
          violet: '#7048e8',
          violetSoft: '#f0ecfe',
          teal: '#0d9488',
        },
      },
      fontFamily: {
        display: ['Epilogue', 'Noto Sans SC', 'sans-serif'],
        sans: ['Noto Sans SC', 'Epilogue', 'sans-serif'],
        mono: ['IBM Plex Mono', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px rgba(24,34,53,0.04), 0 8px 24px -12px rgba(24,34,53,0.10)',
        lift: '0 2px 4px rgba(24,34,53,0.05), 0 16px 40px -16px rgba(24,34,53,0.16)',
        stamp: '0 4px 12px -4px rgba(12,166,120,0.35)',
      },
    },
  },
  plugins: [],
}
