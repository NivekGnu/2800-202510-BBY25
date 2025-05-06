require('dotenv').config();

const express = require('express');
const session = require('express-session');

// A module for a mongoDB database so that users information can be stored
// and don't need to be asked again.
const MongoStore = require('connect-mongo');

// A module to bcrpyt(hash the pw).
const bcrypt = require('bcrypt');

// Generally 12 is adequate. If the round is too high, it takes more time.
const saltRounds = 12;

// Install Joi module to check the data which is sent from the user is valid or not.
const Joi = require('joi');

// Make an express object
const app = express();  

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
/* END secret section */

// Users and Passwords arrays of objects (in memory 'database')
// Need to change this to connect with mongoDB
var {database} = require('./databaseConnection');

app.set('view engine', 'ejs');

// Middleware for to use req.body it is necessary to parse the data.
// Otherwise req.body will be undefined.
app.use(express.urlencoded({extended: false}));

// Sets the location of the database when the new user is created.
const userCollection = database.db(mongodb_db).collection('users');

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

// Routes (root homepage)
app.get('/', (req, res) => {
    res.render("landing");
});

// The route for creating the user.
app.get('/signup', (req,res) => {
    res.render("signup", { title: "Sign Up" });
});

// The route fot log in user.
app.get('/login', (req, res) => {
    res.render("login", { title: "Log in" });
})

// Allows for images, CSS, JS file to be included inyour website.
app.use(express.static(__dirname + "/public"));

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