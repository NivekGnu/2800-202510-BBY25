/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./views/**/*.ejs",  // Path to your EJS templates
    "./templates/**/*.ejs",
    "./*.ejs",
    "./public/**/*.html", // HTML files (if any)
    "./src/**/*.js"      // JS files (if any)
  ],
  theme: {
    extend: {
      colors: {
        'farmer-primary': '#849966',
        'farmer-primary-hover': '#768a5c',
        'farmer-secondary': '#d6d7b8',
        'farmer-secondary-hover': '#c1c1a6',
      },
    },
  },
  plugins: [],
}