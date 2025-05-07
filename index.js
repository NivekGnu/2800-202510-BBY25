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
const e = require('express');

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
    if (req.session.authenticated)
    {
        res.render("home", { title: "Home" });
    } else {
        res.render("landing", { title: "Landing" });
    }
});

// The route for creating the user.
app.get('/signup', (req,res) => {
    res.render("signup", { title: "Sign Up" });
});

// The route for log in user.
app.get('/login', (req, res) => {
    const error = req.session.error;
    delete req.session.error;    
    res.render("login", { title: "Log in" , error: error });
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

// The route for logging in page which checks the matching 
// users with the corresponding pw.
app.post('/loginSubmit', async (req,res) => {
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

    if(validationResult.error != null)
    {
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
    const result = await userCollection.find({email: email})
                    .project({email: 1, password: 1, username: 1, _id: 1}).toArray();

    // How the log in process works (comparing the username and the password)
    // Since it's like an array, if the length is not 1 this means that it didn't 
    // fetch any of it which is an error.
    // In this case, it means that there is no user with the given email and the password.
    if(result.length != 1)
    {
        req.session.error = 'Invalid email/password combination.';
        return res.redirect('/login');
    }

    // result[0] is the first index of an array which is the one fetched by the mongoDB.
    if(await bcrypt.compare(password, result[0].password))
    {
        console.log("correct password");
        
        // This 3 lines of code is storing the data in the session so that
        // it can remember the user when they reaccess with the same session (browser).
        // Saving the username as well from the mongoDB so that it can show it in the root page.
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        // Need to change depending on the user type
        res.redirect('/members');
        return;
    }
    else
    {
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
      lastName:  Joi.string().min(1).required(),
      email:     Joi.string().email().required(),
      password:  Joi.string().min(6).required(),
      role:      Joi.string().valid('buyer', 'seller').required(),
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
    await userCollection.insertOne({ firstName: firstName, lastName: lastName, email: email, password: hashedPassword, role: role, languages: [], createdAt: new Date() })

    req.session.authenticated = true;
    req.session.firstName = firstName;
    req.session.lastName = lastName;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
  
    if (role === 'seller') {
      // take seller to language‑selection page
      return res.render("language", { title: "Select Languages" });
    }
    res.redirect('/');       
});

// route for logging out
app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

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