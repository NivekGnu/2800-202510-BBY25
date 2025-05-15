require('dotenv').config();

const express = require('express');
const session = require('express-session');

// A module for a mongoDB database so that users information can be stored
// and don't need to be asked again.
const MongoStore = require('connect-mongo');

// A module to bcrpyt(hash the pw).
const bcrypt = require('bcrypt');

// multer: Express middleware for handling multipart/form-data, 
// especially used to process file uploads (e.g., images, documents).
const multer = require('multer');

// sharp: High-performance image processing library for Node.js, 
// used to resize, crop, convert formats, and otherwise manipulate images.
const sharp = require('sharp');

// Generally 12 is adequate. If the round is too high, it takes more time.
const saltRounds = 12;

// Install Joi module to check the data which is sent from the user is valid or not.
const Joi = require('joi');

// Make an express object
const app = express();

// extract ObjectId property from object
const { ObjectId } = require('mongodb');

// Google Gemini API
const { GoogleGenAI } = require('@google/genai');

// Set up the time of the duration of the session.
// This code means that session expires after 1 hour.
const expireTime = 1 * 60 * 60 * 1000;

// process.env. lets to access .env file so that it can fetch value(cf. .env).
const port = process.env.PORT || 3000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_db = process.env.MONGODB_DB;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
const google_gemini = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
/* END secret section */

// Users and Passwords arrays of objects (in memory 'database')
// Need to change this to connect with mongoDB
var { database } = require('./databaseConnection');


// Configure Multer to store uploads in memory.
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { filesize: 5 * 1024 * 1024 } // Reject files larger than 5 MB
})

// Sets the location of the database when the new user is created.
const userCollection = database.db(mongodb_db).collection('users');
// Sets the location of the database when the seller creates a post.
const postingCollection = database.db(mongodb_db).collection('posting')

// Need to use the information in the .env file which is defined in the secret section
// (e.g. ${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_db})
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,

    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    // Decide where to store the session data
    store: mongoStore, // default is memory store (server side)
    saveUninitialized: false,
    resave: true
}));

// Middleware for to use req.body it is necessary to parse the data.
// Otherwise req.body will be undefined.
app.use(express.urlencoded({ extended: false }));
// Middleware for parsing JSON data in the request body.
app.use(express.json());
// Allows for images, CSS, JS file to be included inyour website.
app.use(express.static(__dirname + "/public"));

app.set('view engine', 'ejs');

// Routes (root homepage)
app.get('/', async (req, res) => {
    if (req.session.authenticated) {
        if (req.session.role === 'seller') {
            // Fetch all posts by the current seller, sort them newest-first, and return as an array
            // If there is no post then it shows 'no posting' message.
            const docs = await postingCollection
                .find({ sellerId: new ObjectId(req.session.userId) })
                .sort({ createdAt: -1 })
                .toArray();

            // Convert each document's image buffer to Base64 data URI.
            const postings = docs.map(doc => ({
                // Copy over simple fields unchanged:
                produce: doc.produce,
                quantity: doc.quantity,
                price: doc.price,
                description: doc.description,
                createdAt: doc.createdAt,

                //         How it works:
                //  *   1. Base64-encode the Buffer:
                //  *        const base64 = buffer.toString('base64');
                //  *      This turns raw binary data into an ASCII-safe string.
                //  *
                //  *   2. Prepend the Data URI scheme:
                //  *        const dataUri = `data:${mimeType};base64,${base64}`;
                //  *      - `data:` marks this as an inline resource.
                //  *      - `${mimeType}` is the image’s contentType (e.g. "image/jpeg").
                //  *      - `;base64,` tells the browser the following payload is Base64-encoded.
                //  *      - `${base64}` is the actual encoded image data.
                //  *
                //  *   3. Use the Data URI in your HTML:
                //  *        <img src={dataUri} alt="…">
                //  *      The browser decodes the Base64 string on the fly and renders the image.
                imageSrc: `data:${doc.image.contentType};base64,${doc.image.data.toString('base64')}`,

                thumbSrc: `data:${doc.thumbnail.contentType};base64,${doc.thumbnail.data.toString('base64')}`,
            }));

            // Send the data to 'sellerHome.ejs'
            res.render("sellerHome", {
                title: 'My Postings',
                postings: postings
            });
        }

        // reusing code from above for seller
        if (req.session.role === 'buyer') {
            // Fetch all posts, sort them newest-first, and return as an array
            // If there is no post then it shows 'no posting' message.
            const docs = await postingCollection
                .find({}) //find all posts
                .sort({ createdAt: -1 })
                .toArray();

            // Convert each document's image buffer to Base64 data URI.
            const postings = docs.map(doc => ({
                // Copy over simple fields unchanged:
                produce: doc.produce,
                quantity: doc.quantity,
                price: doc.price,
                description: doc.description,
                createdAt: doc.createdAt,

                //         How it works:
                //  *   1. Base64-encode the Buffer:
                //  *        const base64 = buffer.toString('base64');
                //  *      This turns raw binary data into an ASCII-safe string.
                //  *
                //  *   2. Prepend the Data URI scheme:
                //  *        const dataUri = `data:${mimeType};base64,${base64}`;
                //  *      - `data:` marks this as an inline resource.
                //  *      - `${mimeType}` is the image’s contentType (e.g. "image/jpeg").
                //  *      - `;base64,` tells the browser the following payload is Base64-encoded.
                //  *      - `${base64}` is the actual encoded image data.
                //  *
                //  *   3. Use the Data URI in your HTML:
                //  *        <img src={dataUri} alt="…">
                //  *      The browser decodes the Base64 string on the fly and renders the image.
                imageSrc: `data:${doc.image.contentType};base64,${doc.image.data.toString('base64')}`,

                thumbSrc: `data:${doc.thumbnail.contentType};base64,${doc.thumbnail.data.toString('base64')}`,
            }));

            res.render("buyerHome", { title: "Buyer Home Page", mapboxToken: process.env.MAPBOX_API_TOKEN, postings: postings });
        }
    } else {
        res.render("landing", { title: "Landing" });
    }
});

// The route for creating the user.
app.get('/signup', (req, res) => {
    res.render("signup", { title: "Sign Up" });
});

// The route for log in user.
app.get('/login', (req, res) => {
    const error = req.session.error;
    delete req.session.error;
    res.render("login", { title: "Log in", error: error });
})

// The route for the view page
app.get('/viewpage', (req, res) => {
    if (req.session.authenticated) {
        res.render("viewpage", { title: "View Page", username: req.session.username, mapboxToken: process.env.MAPBOX_API_TOKEN });
    } else {
        res.redirect('/login');
    }
});

// The route for the contact page
app.get('/contact', (req, res) => {
    if (req.session.authenticated) {
        res.render("contact", { title: "contact Page", username: req.session.username });
    } else {
        res.redirect('/login');
    }
});

// app.get('/contact', (req, res) => {
//     if (req.session.authenticated) {
//         res.render("navbar", { title: "Navbar", username: req.session.username });
//     } else {
//         res.redirect('/login');
//     }
// });

// The route for logging in page which checks the matching 
// users with the corresponding pw.
app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        }
    );

    // Check
    const validationResult = schema.validate({ email, password }, { abortEarly: false });

    if (validationResult.error != null) {
        // collect all missing/empty field names
        const fields = validationResult.error.details.map(d => d.context.key);
        const unique = Array.from(new Set(fields));

        // build "X is required." for each
        const msgs = unique
            .map(f => `${f} is required.`)
            .join(' ');

        res.send(`
            <p>${msgs}</p>
            <a href="/login">Try again</a>
        `);
        return;
    }

    // Fetch the user info from the MongoDB (Probably fetching only 1)
    const result = await userCollection.find({ email: email })
        .project({ email: 1, password: 1, firstName: 1, lastName: 1, role: 1, _id: 1 }).toArray();

    // How the log in process works (comparing the username and the password)
    // Since it's like an array, if the length is not 1 this means that it didn't 
    // fetch any of it which is an error.
    // In this case, it means that there is no user with the given email and the password.
    if (result.length != 1) {
        req.session.error = 'Invalid email/password combination.';
        console.log("email not associated with any account");
        return res.redirect('/login');
    }

    // result[0] is the first index of an array which is the one fetched by the mongoDB.
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");

        // This 3 lines of code is storing the data in the session so that
        // it can remember the user when they reaccess with the same session (browser).
        // Saving the username as well from the mongoDB so that it can show it in the root page.
        req.session.authenticated = true;
        req.session.email = email;
        req.session.firstName = result[0].firstName;
        req.session.lastName = result[0].lastName;
        req.session.role = result[0].role;
        req.session.cookie.maxAge = expireTime;
        req.session.userId = result[0]._id.toString(); //objectId -clinton

        res.redirect('/');
    }
    else {
        // When the email exists in the database but it does not matches the password.
        console.log("incorrect password");
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <title>Login Error</title>
            </head>
            <body>
              <div class="container">
                <span>Incorrect password</span>
                <br>
                <a href="/login">Try again</a>
              </div>
            </body>
            </html>
            `)
        return;
    }
});

// route for sign up submission
app.post('/signupSubmit', async (req, res) => {
    const { firstName, lastName, email, password, role } = req.body;

    const schema = Joi.object({
        firstName: Joi.string().min(1).required(),
        lastName: Joi.string().min(1).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        role: Joi.string().valid('buyer', 'seller').required(),
    });

    const validationResult = schema.validate({ firstName, lastName, email, password, role });
    if (validationResult.error) {
        return res.status(400).send(validationResult.error.details[0].message);
    }

    // check if email already registered
    const emailExists = await userCollection.findOne({ email });
    if (emailExists) {
        return res.status(400).send('Email already registered');
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // insert into mongoDB
    // extract insertedId property which is ObjectId
    const { insertedId } = await userCollection.insertOne(
        { firstName: firstName, 
            lastName: lastName, 
            email: email, password: hashedPassword, 
            role: role, 
            languages: [], 
            createdAt: new Date() 
        }
    );

    req.session.authenticated = true;
    req.session.firstName = firstName;
    req.session.lastName = lastName;
    // Distinguish user by email to populate post data.
    req.session.email = email;
    req.session.role = role;
    req.session.cookie.maxAge = expireTime;
    req.session.userId = insertedId.toString(); // ObjectId -clinton

    if (req.session.role === 'seller') {
        // take seller to languages page first
        return res.redirect('/languages');
    }

    res.redirect('/');
});

app.get('/languages', (req, res) => {
    if (!req.session.authenticated || req.session.role !== 'seller') {
        return res.redirect('/');
    }
    res.render("languages", { title: "Select Languages" });
});

app.post('/languagesSubmit', async (req, res) => {
    if (!req.session.authenticated || req.session.role !== 'seller') {
        return res.redirect('/');
    }

    // Extract languages from the form post
    let languages = req.body.languages; // could be string "English" or array ["English", "Tagalog"] since urlencoded

    // if nothing checked
    if (!languages) {
        languages = [];
    }

    // if not in array (single language), convert to array
    if (!Array.isArray(languages)) {
        languages = [languages];
    }

    // Update the user document
    await userCollection.updateOne(
        { _id: new ObjectId(req.session.userId) }, // find document w/ given ObjectId
        { $set: { languages: languages } } // set languages
    );
    console.log("languages written into DB");

    res.redirect('/');
});

// route for logging out
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Route for post page
app.get('/createPost', (req, res) => {
    // Redirect to login page when the authentication fails or if the user is not a seller.
    if (!req.session.authenticated || req.session.role !== 'seller') {
        return res.redirect('/login');
    }

    // Render EJS view with a title variable.
    res.render("createPost", { title: 'Create Post', listing: null })
});

//     Route for POST / createPost
//     Handle form submission:
//       a) Validate session as seller.
//       b) Extract form data.
//       c) Resize images into full-size and thumbnail.
//       d) Save image files as buffer so that it can be stored in the MongoDB.
//       e) Insert a document in 'posting' collection.
//       upload.single('image'): Multer middleware to accept one file 
//       from the form field named "image" and make it available as req.file
app.post('/createPost', upload.single('image'), async (req, res) => {
    // a) session check
    if (!req.session.authenticated || req.session.role !== 'seller') {
        return res.redirect('/login');
    }

    // b) extract fields from the body (form - name field)
    const { produce, quantity, price, description } = req.body

    // Create a filesystem-safe base filename:
    // timestamp + hyphenated produce name in lowercase.
    const timestamp = Date.now()
    const safeName = produce.replace(/\s+/g, '-').toLowerCase()
    const baseName = `${timestamp}-${safeName}`

    // 1) Generate full-size JPEG buffer.
    // Buffer is like a 'byte-bowl' which lets you safely save 
    // binary data such as files, images etc.
    const fullBuffer = await sharp(req.file.buffer)
        .resize({ width: 1080 })
        .jpeg({ quality: 80, progressive: true })
        .toBuffer();

    // 2) Generate thumbnail buffer
    const thumbBuffer = await sharp(req.file.buffer)
        .resize({ width: 400 })
        .jpeg({ quality: 70 })
        .toBuffer();

    // Adding data to MongoDB 'post'.
    await postingCollection.insertOne({
        produce,
        quantity: parseInt(quantity, 10),
        price,
        description,
        image: {
            data: fullBuffer,                   // <-- binary image data
            contentType: 'image/jpeg'           // <-- for serving later
        },
        thumbnail: {
            data: thumbBuffer,
            contentType: 'image/jpeg'
        },
        sellerId: new ObjectId(req.session.userId), // Stores the seller's id in the posting collection field.
        createdAt: new Date()
    })

    res.redirect('/');
})

// The route for the chat page
app.get('/chat', (req, res) => {
    if (req.session.authenticated) {
        res.render("chat", { title: "Chat", firstName: req.session.firstName });
    }
    else {
        res.redirect('/login');
    }
});

// Route for maps page
app.get('/map', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    res.render('map', { title: 'Map', mapboxToken: process.env.MAPBOX_API_TOKEN });
});

app.get('/test', (req, res) => {
    res.render('test', { title: 'Test', mapboxToken: process.env.MAPBOX_API_TOKEN, google_gemini: google_gemini });
});

// Gemini API route
app.post('/api/gemini', async (req, res) => {
  try {
    const prompt = req.body.prompt;

    if (!prompt) {
      return res.status(400).json({ error: 'Missing prompt' });
    }

    const result = await google_gemini.models.generateContent({ model: 'gemini-1.5-flash', contents: prompt });

    return res.json(result.text); // get res.text and send as JSON object


  } catch (err) {
    console.error(err);
    console.error("Gemini error:", err);
    res.status(500).json({ error: 'Gemini API call failed.' });
  }
});

app.post('/testPost', (req, res) => {
    const {'address address-search': address, city, province, postalCode} = req.body;

    console.log(JSON.stringify(req.body));
    res.send(`
        req.body: ${JSON.stringify(req.body)}
        
        <h1>Test Post</h1>
        <p>Address: ${address}</p>
        <p>City: ${city}</p>
        <p>Province: ${province}</p>
        <p>Postal Code: ${postalCode}</p>
        <a href="/test">Back</a>
        `)
});
     

// 404 Page, must be placed at the end of all the routes.
// but before "app.listen".
app.use((req, res) => {
    res.status(404);
    res.render("404", { title: "Error" });
});


// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ` + port);
});