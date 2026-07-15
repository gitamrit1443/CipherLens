/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{html,ts}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"]
      }
    }
  },
  daisyui: {
    themes: [
      {
        cipherlens: {
          primary: "#2563eb",
          secondary: "#0f766e",
          accent: "#e11d48",
          neutral: "#111827",
          "base-100": "#f8fafc",
          "base-200": "#eef2f7",
          "base-300": "#d7dee8",
          info: "#0284c7",
          success: "#16a34a",
          warning: "#d97706",
          error: "#dc2626"
        }
      }
    ]
  },
  plugins: [require("daisyui")]
};
