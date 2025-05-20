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
    extend: {},
  },
  plugins: [],
}