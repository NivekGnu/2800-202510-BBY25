# COMP2800-BBY25

Project Title: Farmer's Marketplace

Farmer's Marketplace is a web and mobile platform that connects small-scale farmers in Vancouver and the Lower Mainland with local buyers.

## About Us
Team Name: BBY-25
Team Members: 
- Tommy Nguyen
- Kevin Ung
- Shawn Lee
- Clinton Nguyen

## Technologies Used
- Front-end
  - HTML
  - CSS/Tailwindcss
  - Javascript
  - Leaflet API 
  - Mapbox for map tileset
- Back-end
  - Node.js
  - Express.js
  - Google Gemini
  - Socket.io
  - Stripe
- Database
  - MongoDB

## File Contents
Full listing of files can be found in full_file_list.txt

## How to Get It Running!
1. Ensure you first have the following:
  - Any IDE for web dev (we recommend VSCode for easy extension installations!)
  - MongoDB account (install Studio3t if you do not want to use mongoDB on the web)
  - Node.js

2. Required third party API's: Please install in project folder AFTER intalling Node.js
  - Express.js (npm i express): Must be at least 5.x.x (Use npm list express)
  - Express sessions (npm i express-session): Handling user sessions on the web
  - Connect-mongo (npm i connect-mongo): To connect to the mongoDB
  - EJS (npm i ejs): For rendering ejs pages on the web
  - BCrypt (npm i bcrypt): User encryption
  - Dotenv (npm i dotenv): For keeping our API keys separate from our code
  - JOI (npm i joi): Input validator
  - Multer (npm i multer): Used for handling images
  - Socket.io (npm i socket.io): For live chat between buyer and seller
  - Stripe (npm i stripe): Used for online payments
  - Leaflet (npm i leaflet): For Map API
  - Tailwindcss (npm i tailwindcss): For our app styling
    - For testing you can put "<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>" in the head
    - **PLEASE DO NOT USE FOR ACTUAL RELEASE**
  - Google Gemini (npm i @google/generative-ai)
  
3. Required APIs **IMPORTANT: PLEASE ENSURE YOU KEEP API KEYS IN A ".env" FILE**.
Obtain API keys for the following (account for each required)
 - MongoDB
 - Mapbox
 - Gemini
 - Stripe
 - Create two session secrets (for node and mongodb) with any UUID generator (ie. https://www.uuidgenerator.net/)

Then copy the following into your ".env" file and replace '{YOUR KEY}' with your API key **NO SPACE**

- MONGODB_HOST={YOUR KEY}
- MONGODB_USER={YOUR KEY}
- MONGODB_PASSWORD={YOUR KEY}
- MONGODB_DATABASE={YOUR KEY}
- MONGODB_SESSION_SECRET={YOUR KEY}
- NODE_SESSION_SECRET={YOUR KEY}
- MAPBOX_API_TOKEN={YOUR KEY}
- GEMINI_API_KEY={YOUR KEY}
- STRIPE_PUBLISHABLE_KEY={YOUR KEY}
- STRIPE_SECRET_KEY={YOUR KEY}
- STRIPE_WEBHOOK_SECRET={YOUR KEY}

4. Fork this repository for yourself and place your ".env" in the folder.
It should be in the main folder (you should see index.js as well)

5. Use "node index.js" to get it running locally (ie. http://localhost:3000/)
  - Bonus: use "nodemon index.js" if you want the server to refresh with you changes after you save them (ctrl + s)
  - **You may need to install nodemon (npm i nodemon)**

## Features
 - Purchase fresh produce directly form the farmer
 - Create, edit, and delete postings 
 - Live map that shows location of local seller's
 - Filter postings by type of produce (ie. fruits or vegetables) or seller's spoken language
 - Live chat with the seller to ask questions
 - "Magic" AI button that asks Gemini what produce is in season within BC

## Credits, References, Liscenses
1. Credits
  - Google Gemini: Used in our "magic" button to display a response (check AI acknowledgement)
  - Tailwindcss - Styling our app
  - Iconmonstr - Icons used in our navbar

2. References
  - MDN Web Docs: Reading over syntax for Javascript (ie. geolocation for user's location)
  - Tailwindcss Docs: For class references (play.tailwindcss.com to practice)
  - Gemini Docs: How to setup and use Gemini within our app
  - Stack Overflow: Resolve issues or finding solutions/explanations not found in documentation

## API Usages
 - Leaflet used for the map
 - Stripe is used for allowing payments

## AI acknowledgements
AI was used in this project for:
  - Generating the logo
  - Generating a response for the question "What produce is currently in season in BC?"


## Contact Info
- Tommy Nguyen: tnguyen630@my.bcit.ca
- Kevin Ung: kung3@my.bcit.ca
- Shawn Lee: slee1109@my.bcit.ca
- Clinton Nguyen: cnguyen136@my.bcit.ca
