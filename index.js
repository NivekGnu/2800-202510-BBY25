require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const multer = require("multer");
const sharp = require("sharp");
const Joi = require("joi");
const { ObjectId } = require("mongodb");
const http = require("http"); // Required for Socket.IO
const { Server } = require("socket.io"); // Required for Socket.IO
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // required for Stripe
const LIVE_DOMAIN = process.env.LIVE_DOMAIN || 'http://localhost:3000'; // needed for Stripe redirect


const saltRounds = 12;
const app = express();
const server = http.createServer(app); // Create HTTP server for Socket.IO
const io = new Server(server, {
  cors: {
    origin: "*", // Be more specific in production, e.g., "http://localhost:3000" or your frontend URL
    methods: ["GET", "POST"],
  },
});

// Google Gemini API
const { GoogleGenerativeAI } = require('@google/generative-ai');

// Set up the time of the duration of the session.
// This code means that session expires after 1 hour.
const expireTime = 1 * 60 * 60 * 1000;

// process.env. lets to access .env file so that it can fetch value(cf. .env).
const port = process.env.PORT || 3000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_db = process.env.MONGODB_DB;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const google_gemini = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiModel = google_gemini.getGenerativeModel({ model: "gemini-2.0-flash" });
/* END secret section */

var { database } = require("./databaseConnection"); // Assuming this file exports a connected MongoDB client

// Configure Multer for in-memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { filesize: 5 * 1024 * 1024 }, // 5 MB file size limit
});

// MongoDB Collection definitions
const userCollection = database.db(mongodb_db).collection("users");
const postingCollection = database.db(mongodb_db).collection("posting");
const chatMessageCollection = database
  .db(mongodb_db)
  .collection("chatMessages");

// Configure MongoStore for session storage
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`, // Storing sessions in a 'sessions' collection/db
  crypto: {
    secret: mongodb_session_secret,
  },
});

// Session middleware setup
const sessionMiddleware = session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true, // Consider setting to false if your store supports touch
  cookie: { maxAge: expireTime },
});
app.use(sessionMiddleware);

// Share session middleware with Socket.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

// endpoint for Stripe ---- MUST BE PLACED BEFORE EXPRESS.JSON()... REQUIRES RAW REQUEST BODY ---- 
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    let event = stripe.webhooks.constructEvent(
        req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
    );
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        // Record the transaction
        await database.db(mongodb_db).collection('transactions').insertOne({
            buyerId: new ObjectId(session.metadata.buyerId),
            sellerId: new ObjectId(session.metadata.sellerId),
            transactionId: session.payment_intent,
            amount: session.amount_total / 100,
            currency: session.currency,
            createdAt: new Date(session.created * 1000), // JS expects MS so multiply by 1000
        });
    }
    res.sendStatus(200);
});

// Express middleware
app.use(express.urlencoded({ extended: false }));
// Middleware for parsing JSON data in the request body.
app.use(express.json());
// Allows for images, CSS, JS file to be included inyour website.
app.use(express.static(__dirname + "/public"));
app.set("view engine", "ejs");

// Middleware to make session available to all EJS templates
app.use((req, res, next) => {
  res.locals.session = req.session; // Makes req.session available as `session` in EJS
  next();
});

// --- ROUTES ---

// Root homepage
app.get('/', async (req, res) => {
  if (req.session.authenticated) {
    if (req.session.role === 'seller') {
      const docs = await postingCollection
        .find({ sellerId: new ObjectId(req.session.userId) })
        .sort({ createdAt: -1 })
        .toArray();

      const postings = docs.map(doc => ({
        // For fetching the correct post, it needs the id of the post.
        id: doc._id,
        produce: doc.produce,
        quantity: doc.quantity,
        price: doc.price,
        description: doc.description,
        createdAt: doc.createdAt,
        imageSrc: `data:${doc.image.contentType};base64,${doc.image.data.toString('base64')}`,
        thumbSrc: `data:${doc.thumbnail.contentType};base64,${doc.thumbnail.data.toString('base64')}`,
      }));

      res.render("sellerHome", {
        title: 'My Postings',
        postings: postings,
        mapboxToken: process.env.MAPBOX_API_TOKEN
      });
    } else if (req.session.role === 'buyer') {
      const docs = await postingCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      const postings = docs.map(doc => ({
        produce: doc.produce,
        quantity: doc.quantity,
        price: doc.price,
        description: doc.description,
        createdAt: doc.createdAt,
        imageSrc: `data:${doc.image.contentType};base64,${doc.image.data.toString('base64')}`,
        thumbSrc: `data:${doc.thumbnail.contentType};base64,${doc.thumbnail.data.toString('base64')}`,
      }));

      res.render("buyerHome", {
        title: "Buyer Home Page",
        mapboxToken: process.env.MAPBOX_API_TOKEN,
        postings: postings
      });
    } else {
      // Should not happen if role is always set, but as a fallback:
      res.redirect("/login");
    }
  } else {
    res.render("landing", { title: "Landing" });
  }
});

// For Gemini Calls
// Gemini API route
app.post('/api/gemini', async (req, res) => {
  try {
    const prompt = req.body.prompt;
    if (!prompt) return res.status(400).json({ error: 'Missing prompt' });

    const result = await geminiModel.generateContent(prompt);
    const response = await result.response;
    const text = response.text();

    return res.json({ text });
  } catch (err) {
    console.error("Gemini error:", err);
    res.status(500).json({ error: 'Gemini API call failed.' });
  }
});

// Signup page
app.get("/signup", (req, res) => {
  res.render("signup", { title: "Sign Up", mapboxToken: process.env.MAPBOX_API_TOKEN });
});

// Login page
app.get("/login", (req, res) => {
  const error = req.session.error;
  delete req.session.error; // Clear error after displaying
  res.render("login", { title: "Log in", error: error });
});

// Login submission
app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(), // Max length for password
  });

  const validationResult = schema.validate({ email, password }, { abortEarly: false });
  if (validationResult.error) {
    const fields = validationResult.error.details.map((d) => d.context.key);
    const uniqueFields = Array.from(new Set(fields));
    const errorMessages = uniqueFields.map((f) => `${f} is invalid or missing.`).join(" ");
    // req.session.error = errorMessages; // Option: set session error and redirect
    // return res.redirect("/login");
    return res.status(400).send(`<p>${errorMessages}</p><a href="/login">Try again</a>`);
  }

  try {
    const user = await userCollection.findOne({ email: email });
    if (!user) {
      req.session.error = "Invalid email or password.";
      return res.redirect("/login");
    }

    if (await bcrypt.compare(password, user.password)) {
      req.session.authenticated = true;
      req.session.email = user.email;
      req.session.firstName = user.firstName;
      req.session.lastName = user.lastName;
      req.session.role = user.role;
      req.session.userId = user._id.toString();
      // req.session.cookie.maxAge = expireTime; // Already set globally

      console.log("Login successful for:", user.email);
      return res.redirect("/");
    } else {
      req.session.error = "Invalid email or password.";
      return res.redirect("/login");
    }
  } catch (error) {
    console.error("Login error:", error);
    req.session.error = "An error occurred during login. Please try again.";
    return res.redirect("/login");
  }
});

// Signup submission
app.post("/signupSubmit", async (req, res) => {
  const { firstName, lastName, email, password, role, 'address address-search': address, city, province, postalCode } = req.body;
  const schema = Joi.object({
    firstName: Joi.string().alphanum().min(1).max(50).required(),
    lastName: Joi.string().alphanum().min(1).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(100).required(), 
    role: Joi.string().valid("buyer", "seller").required(),
  });

  const { error } = schema.validate(
    { firstName, lastName, email, password, role },
    { abortEarly: false }
  );

  if (error) {
    return res
      .status(400)
      .send(`${error.details[0].message} <a href="/signup">Try again</a>`);
  }

  try {
    const emailExists = await userCollection.findOne({ email });
    if (emailExists) {
      return res.status(400).send(
        'Email already registered. <a href="/login">Login</a> or <a href="/signup">try another email</a>.'
      );
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = {
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role,
      languages: role === "seller" ? [] : undefined, // Only sellers have languages initially
      createdAt: new Date(),
    };

    if(newUser.role === "seller") {
      newUser.address = {address, city, province, postalCode}
    }

    const result = await userCollection.insertOne(newUser);

    req.session.authenticated = true;
    req.session.firstName = firstName;
    req.session.lastName = lastName;
    req.session.email = email;
    req.session.role = role;
    req.session.userId = result.insertedId.toString();
    // req.session.cookie.maxAge = expireTime; // Already set globally

    console.log("Signup successful for:", email);

    if (role === "seller") {
        const account = await stripe.accounts.create({
            type: 'express',
            email,
            business_type: 'individual',
            capabilities: {transfers: { requested: true }}
        });

        // Save Stripe account ID in mongoDB
        await userCollection.updateOne(
            { _id: new ObjectId(req.session.userId) },
            { $set: { stripeAccountId: account.id } }
        );

        return res.redirect("/languages");
    }
    return res.redirect("/");
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(500).send("Error creating account. <a href='/signup'>Try again</a>");
  }
});

// Languages selection page (for sellers)
app.get("/languages", (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/"); // Or /login
  }
  res.render("languages", { title: "Select Languages" });
});

// Languages submission
app.post("/languagesSubmit", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/");
  }

  let languages = req.body.languages;
  if (!languages) {
    languages = [];
  } else if (!Array.isArray(languages)) {
    languages = [languages]; // Ensure it's an array
  }

  try {
    await userCollection.updateOne(
      { _id: new ObjectId(req.session.userId) },
      { $set: { languages: languages } }
    );
    console.log(`Languages updated for user ${req.session.userId}:`, languages);
    return res.redirect("/");
  } catch (error) {
    console.error("Error updating languages:", error);
    // Optionally, provide feedback to the user
    return res.status(500).send("Error updating languages. <a href='/languages'>Try again</a>");
  }
});

// Logout
app.get("/logout", (req, res) => {
  const userEmail = req.session.email;
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
      return res.status(500).send("Could not log out. Please try again.");
    }
    console.log("User logged out:", userEmail || "Unknown user");
    return res.redirect("/");
  });
});

// Create post page (for sellers)
app.get("/createPost", (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/login");
  }
  res.render("createPost", { title: "Create Post", listing: null }); // `listing: null` for consistency if edit uses same template
});

// Create post submission
app.post("/createPost", upload.single("image"), async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.status(403).redirect("/login");
  }
  if (!req.file) {
    return res.status(400).send("No image uploaded. <a href='/createPost'>Try again</a>");
  }

  const { produce, quantity, price, description } = req.body;
  // Basic validation for other fields (Joi could be used here too for more robustness)
  if (!produce || !quantity || !price) {
    return res.status(400).send("Missing required fields (produce, quantity, price). <a href='/createPost'>Try again</a>");
  }

  try {
    const fullBuffer = await sharp(req.file.buffer)
      .resize({ width: 1080, withoutEnlargement: true })
      .jpeg({ quality: 80, progressive: true })
      .toBuffer();
    const thumbBuffer = await sharp(req.file.buffer)
      .resize({ width: 400, withoutEnlargement: true })
      .jpeg({ quality: 70 })
      .toBuffer();

    await postingCollection.insertOne({
      produce,
      quantity: parseInt(quantity, 10),
      price: parseFloat(price),
      description,
      image: { data: fullBuffer, contentType: "image/jpeg" },
      thumbnail: { data: thumbBuffer, contentType: "image/jpeg" },
      sellerId: new ObjectId(req.session.userId),
      createdAt: new Date(),
    });
    console.log("New post created by:", req.session.email);
    return res.redirect("/");
  } catch (error) {
    console.error("Error creating post:", error);
    return res.status(500).send("Error processing your post. <a href='/createPost'>Try again</a>");
  }
});

// EDIT POST (Seller)
app.get("/post/:id/edit", async (req, res) => {

  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/login");
  }

  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).send("Invalid post ID");
  }

  const doc = await postingCollection.findOne({ _id: new ObjectId(id) });
  if (!doc) {
    return res.status(404).send("Post not found");
  }

  // Build a "currentPost" object just like in sellerHome
  const currentPost = {
    id: doc._id.toString(),
    produce: doc.produce,
    quantity: doc.quantity,
    price: doc.price,
    description: doc.description,
    // show current full-size image for preview
    imageUrl: `data:${doc.image.contentType};base64,${doc.image.data.toString("base64")}`
  };

  res.render("editPost", { title: "Edit Post", currentPost });
});

// POST updated data
app.post("/post/:id/edit", upload.single("image"), async (req, res) => {

  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/login");
  }

  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).send("Invalid post ID");
  }

  const { produce, quantity, price, description } = req.body;
  const updateDoc = {
    $set: {
      produce,
      quantity: parseInt(quantity, 10),
      price: parseFloat(price),
      description
    }
  };

  // If seller uploads a new image, regenerate full image + thumbnail
  if (req.file) {
    const fullBuffer = await sharp(req.file.buffer)
      .resize({ width: 1080, withoutEnlargement: true })
      .jpeg({ quality: 80 })
      // Runs the pipeline and returns a new Buffer containing the processed JPEG bytes
      // Buffer is Node's way of representing a raw binary data
      .toBuffer();

    const thumbBuffer = await sharp(req.file.buffer)
      .resize({ width: 400, withoutEnlargement: true })
      .jpeg({ quality: 70 })
      .toBuffer();

    updateDoc.$set.image = { data: fullBuffer, contentType: "image/jpeg" };
    updateDoc.$set.thumbnail = { data: thumbBuffer, contentType: "image/jpeg" };
  }

  await postingCollection.updateOne(
    { _id: new ObjectId(id) },
    updateDoc
  );

  res.redirect("/"); // Back to sellerHome
});

// --- CHAT ROUTES ---
app.get("/chat", async (req, res) => {
  console.log("GET /chat route. Query:", req.query, "Session UserID:", req.session.userId);
  if (!req.session.authenticated) {
    console.log("GET /chat - Unauthenticated, redirecting to login.");
    return res.redirect("/login");
  }

  const currentUserId = req.session.userId;
  const otherUserIdString = req.query.with;
  let errorMessage = "";

  if (!otherUserIdString) errorMessage = "No user specified to chat with. Append ?with=USER_ID to the URL.";
  else if (!ObjectId.isValid(otherUserIdString)) errorMessage = "The user ID for your chat partner is invalid.";
  else if (currentUserId === otherUserIdString) errorMessage = "You cannot start a chat with yourself.";

  if (errorMessage) {
    console.log("GET /chat - Error condition:", errorMessage);
    return res.status(400).render("errorPage", { title: "Chat Error", errorMessage });
  }

  try {
    const otherUser = await userCollection.findOne(
      { _id: new ObjectId(otherUserIdString) },
      { projection: { firstName: 1, lastName: 1 } }
    );

    if (!otherUser) {
      console.log("GET /chat - Other user not found:", otherUserIdString);
      return res.status(404).render("errorPage", {
        title: "Chat Error",
        errorMessage: "The user you are trying to chat with could not be found.",
      });
    }

    const ids = [currentUserId, otherUserIdString].sort();
    const chatId = ids.join("-");
    console.log("GET /chat - Rendering chat page for chatId:", chatId);
    return res.render("chat", {
      title: `Chat with ${otherUser.firstName}`,
      currentUserId,
      currentUserFirstName: req.session.firstName,
      otherUserId: otherUserIdString,
      otherUserName: `${otherUser.firstName} ${otherUser.lastName || ""}`.trim(),
      chatId,
    });
  } catch (error) {
    console.error("GET /chat - CRITICAL ERROR setting up chat page:", error.stack);
    return res.status(500).render("errorPage", {
      title: "Server Error",
      errorMessage: "An internal error occurred while trying to load the chat page.",
    });
  }
});

app.get("/api/chat/:chatId/messages", async (req, res) => {
  console.log("GET /api/chat/:chatId/messages - Received for chatId:", req.params.chatId, "Session UserID:", req.session.userId);
  if (!req.session.authenticated) return res.status(401).json({ error: "Unauthorized" });

  try {
    const { chatId } = req.params;
    const currentUserId = req.session.userId;
    const [user1, user2] = chatId.split("-");

    if (user1 !== currentUserId && user2 !== currentUserId) {
      return res.status(403).json({ error: "Forbidden: Not part of this chat." });
    }

    const messagesFromDb = await chatMessageCollection
      .find({ chatId })
      .sort({ timestamp: 1 })
      .toArray();

    const messages = messagesFromDb.map((msg) => ({
      _id: msg._id.toString(),
      chatId: msg.chatId,
      senderId: msg.senderId.toString(),
      receiverId: msg.receiverId.toString(), // Ensure receiverId is also a string
      messageType: msg.messageType,
      timestamp: msg.timestamp,
      messageText: msg.messageText || "",
      ...(msg.messageType === "image" && msg.image?.data && {
        imageDataUri: `data:${msg.image.contentType};base64,${msg.image.data.toString("base64")}`,
      }),
    }));
    console.log("GET /api/chat/:chatId/messages - Sending", messages.length, "messages.");
    return res.json(messages);
  } catch (error) {
    console.error("GET /api/chat/:chatId/messages - CRITICAL ERROR:", error.stack);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Server error fetching messages.", details: error.message });
    }
  }
});

app.post("/api/chat/messages", async (req, res) => {
  console.log("POST /api/chat/messages RECEIVED. Session UserID:", req.session.userId, "Body:", req.body);
  if (!req.session.authenticated) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const { chatId, senderId, receiverId, messageText } = req.body;
    let errors = [];
    if (!chatId || typeof chatId !== "string" || !chatId.includes("-")) errors.push("Invalid or missing chatId.");
    if (!senderId || senderId !== req.session.userId) errors.push("Invalid or mismatched senderId.");
    if (!receiverId || typeof receiverId !== "string") errors.push("Invalid or missing receiverId.");
    if (!messageText || typeof messageText !== "string" || messageText.trim() === "") errors.push("Message text is empty or invalid.");
    if (senderId && !ObjectId.isValid(senderId)) errors.push("SenderId is not a valid ObjectId format.");
    if (receiverId && !ObjectId.isValid(receiverId)) errors.push("ReceiverId is not a valid ObjectId format.");

    if (errors.length > 0) {
      console.log("API /api/chat/messages - Validation Errors:", errors.join(" "));
      return res.status(400).json({ error: "Invalid message data.", details: errors.join(" ") });
    }

    const [user1, user2] = chatId.split("-");
    if (user1 !== req.session.userId && user2 !== req.session.userId) {
      return res.status(403).json({ error: "Forbidden: Not part of this chat." });
    }

    const newMessageDocument = {
      chatId,
      senderId: new ObjectId(senderId),
      receiverId: new ObjectId(receiverId),
      messageText: messageText.trim(),
      messageType: "text",
      timestamp: new Date(),
    };

    const result = await chatMessageCollection.insertOne(newMessageDocument);
    const savedMessage = {
      ...newMessageDocument,
      _id: result.insertedId.toString(),
      senderId: newMessageDocument.senderId.toString(),
      receiverId: newMessageDocument.receiverId.toString(),
    };

    console.log("API /api/chat/messages - Message saved. Emitting via Socket.IO to room:", chatId);
    io.to(chatId).emit("newMessage", savedMessage);
    return res.status(201).json(savedMessage);
  } catch (error) {
    console.error("CRITICAL ERROR in POST /api/chat/messages:", error.stack);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Server error while sending message.", details: error.message });
    }
  }
});

app.post("/api/chat/messages/image", upload.single("chatImage"), async (req, res) => {
  console.log("POST /api/chat/messages/image RECEIVED. Session UserID:", req.session.userId, "Body:", req.body, "File:", req.file ? req.file.originalname : "No file");
  if (!req.session.authenticated) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const { chatId, senderId, receiverId, caption } = req.body; // caption is optional
    let errors = [];
    if (!req.file) errors.push("No image file was uploaded.");
    if (!chatId || typeof chatId !== "string" || !chatId.includes("-")) errors.push("Invalid or missing chatId.");
    if (!senderId || senderId !== req.session.userId) errors.push("Invalid or mismatched senderId.");
    if (!receiverId || typeof receiverId !== "string") errors.push("Invalid or missing receiverId.");
    if (senderId && !ObjectId.isValid(senderId)) errors.push("SenderId is not a valid ObjectId format.");
    if (receiverId && !ObjectId.isValid(receiverId)) errors.push("ReceiverId is not a valid ObjectId format.");

    if (errors.length > 0) {
      console.log("API /api/chat/messages/image - Validation Errors:", errors.join(" "));
      return res.status(400).json({ error: "Invalid image message data.", details: errors.join(" ") });
    }

    const [user1, user2] = chatId.split("-");
    if (user1 !== req.session.userId && user2 !== req.session.userId) {
      return res.status(403).json({ error: "Forbidden: Not part of this chat." });
    }

    const imageBuffer = await sharp(req.file.buffer)
      .resize({ width: 800, withoutEnlargement: true })
      .jpeg({ quality: 75 })
      .toBuffer();

    const newMessageDocument = {
      chatId,
      senderId: new ObjectId(senderId),
      receiverId: new ObjectId(receiverId),
      messageText: caption || "", // caption for the image
      image: { data: imageBuffer, contentType: "image/jpeg" },
      messageType: "image",
      timestamp: new Date(),
    };

    const result = await chatMessageCollection.insertOne(newMessageDocument);
    const savedMessage = {
      _id: result.insertedId.toString(),
      chatId,
      senderId: newMessageDocument.senderId.toString(),
      receiverId: newMessageDocument.receiverId.toString(),
      messageType: "image",
      timestamp: newMessageDocument.timestamp,
      messageText: newMessageDocument.messageText,
      imageDataUri: `data:image/jpeg;base64,${imageBuffer.toString("base64")}`,
    };

    console.log("API /api/chat/messages/image - Image message saved. Emitting via Socket.IO to room:", chatId);
    io.to(chatId).emit("newMessage", savedMessage);
    return res.status(201).json(savedMessage);
  } catch (error) {
    console.error("CRITICAL ERROR in POST /api/chat/messages/image:", error.stack);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Server error while sending image message.", details: error.message });
    }
  }
});

// cart route
app.get('/cart', (req,res) => {
    if (req.session.authenticated && req.session.role === 'buyer') {
        return res.render("cart", { title: "Cart"});
    } else {
        res.redirect("/");
    }
});

//checkout route
app.post('/checkout', async (req, res) => {
    const { sellerId, cartItems } = req.body;

    // get Stripe acc id for seller
    const seller = await userCollection.findOne({ _id: new ObjectId(sellerId) });
    if (!seller || !seller.stripeAccountId) {
        return res.status(400).send('Invalid seller');
    }

    // map list of items in cart to Stripe line_items
    const line_items = cartItems.map(item => ({
        price_data: {
            currency: 'cad',
            product_data: { name: item.produce }, // name of item
            unit_amount: Math.round(item.price * 100), // eg. $3.25 to 325 cents
        },
        quantity: item.quantity,                     
    }));

    // create the Checkout Session; create payment intent
    const checkoutSession = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items,
        mode: 'payment',
        payment_intent_data: {
            application_fee_amount: 0,
            transfer_data: { destination: seller.stripeAccountId }, // send money to seller's stripe acc 
        },
        success_url: `${LIVE_DOMAIN}/checkout/success`, //change later
        cancel_url: `${LIVE_DOMAIN}/cartout/fail`, //change later
        metadata: {
            buyerId: req.session.userId,
            sellerId: sellerId,
        },
    });

    res.json({ url: checkoutSession.url });
});

// --- OTHER MISC ROUTES ---
// Viewpage route
app.get('/viewpage', (req, res) => {
  if (req.session.authenticated) {
    // Using firstName as username was not explicitly set in session previously
    res.render("viewpage", {
      title: "View Page",
      firstName: req.session.firstName, // Changed from username
      mapboxToken: process.env.MAPBOX_API_TOKEN
    });
  } else {
    res.redirect('/login');
  }
});

// Contact page route
app.get('/contact', (req, res) => {
  if (req.session.authenticated) {
    // Using firstName as username was not explicitly set in session previously
    res.render("contact", {
      title: "Contact Page", // Corrected title
      firstName: req.session.firstName // Changed from username
    });
  } else {
    res.redirect('/login');
  }
});

// Map page route
app.get("/map", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");

  const sellers = await userCollection.find({ role: "seller" }).toArray();

  res.render("map", {
    title: "Map",
    mapboxToken: process.env.MAPBOX_API_TOKEN,
    sellers: sellers
  });
});

// --- SOCKET.IO CONNECTION LOGIC ---
io.on("connection", (socket) => {
  console.log("A user connected via WebSocket:", socket.id);
  const session = socket.request.session; // Access session data from socket handshake

  if (!session || !session.authenticated) {
    console.log("Socket connection from unauthenticated user. Disconnecting.", socket.id);
    socket.disconnect(true); // Disconnect unauthenticated users
    return;
  }

  console.log(`User ${session.firstName} (${session.userId}) connected with socket ${socket.id}`);

  socket.on("joinChat", (chatId) => {
    if (chatId && typeof chatId === "string" && chatId.includes("-")) {
      console.log(`Socket ${socket.id} (User: ${session.userId}) joining chat room: ${chatId}`);
      socket.join(chatId);
    } else {
      console.log(`Socket ${socket.id} (User: ${session.userId}) tried to join an invalid chat room: '${chatId}'`);
    }
  });

  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.id} (User: ${session.firstName || "Unknown"} - ${session.userId || "Unknown"})`);
    // Potential: Remove user from any rooms they were in, or update presence status
  });

  // Example: Listen for other custom events from client
  // socket.on('typing', (data) => {
  //   if (data.chatId) {
  //     socket.to(data.chatId).emit('userTyping', { userId: session.userId, isTyping: data.isTyping });
  //   }
  // });
});

// --- 404 AND GLOBAL ERROR HANDLER ---

// 404 Not Found Handler (must be after all other routes)
app.use((req, res, next) => {
  console.log("404 Not Found:", req.originalUrl);
  res.status(404).render("404", { title: "Page Not Found" });
});

// Global Error Handler (must be the last app.use())
app.use((err, req, res, next) => {
  console.error("Global error handler caught an error for URL:", req.originalUrl);
  console.error(err.stack); // Log the full error stack

  if (!res.headersSent) {
    return res.status(err.status || 500).render("errorPage", {
      title: "Server Error",
      errorMessage: err.message || "An unexpected server error occurred. Please try again later.",
      // In development, you might want to pass the error object:
      // error: process.env.NODE_ENV === 'development' ? err : {}
    });
  }
  // If headers already sent, delegate to default Express error handler
  next(err);
});

// Start the server
server.listen(port, () => { // Use server.listen for Socket.IO
  console.log(`Server with Socket.IO is running on port ${port}`);
});
