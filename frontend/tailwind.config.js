/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        canvas: '#f5f6f8',
        surface: '#ffffff',
        ink: {
          DEFAULT: '#0f172a',
          soft: '#475569',
          faint: '#8b95a5',
        },
        line: {
          DEFAULT: '#e4e8ee',
          strong: '#cbd5e1',
        },
        accent: {
          50: '#eef4ff',
          100: '#dbe7ff',
          200: '#bfd3fe',
          500: '#2563eb',
          600: '#1d4ed8',
          700: '#1e40af',
        },
        ok: { DEFAULT: '#15803d', soft: '#f0fdf4' },
        bad: { DEFAULT: '#b91c1c', soft: '#fef2f2' },
        warn: { DEFAULT: '#b45309', soft: '#fffbeb' },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', '"Segoe UI"',
               '"Noto Sans SC"', '"PingFang SC"', '"Microsoft YaHei"',
               'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas',
               '"Liberation Mono"', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px rgba(15, 23, 42, 0.03)',
        pop: '0 12px 32px -12px rgba(15, 23, 42, 0.22)',
      },
    },
  },
  plugins: [],
}
