// server.js (or your main application file)

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
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const saltRounds = 12;
const app = express();
const server = http.createServer(app); // Create HTTP server from Express app
const io = new Server(server, {
  // Attach Socket.IO to the HTTP server
  cors: {
    origin: "*", // Adjust for production
    methods: ["GET", "POST"],
  },
});

const { GoogleGenerativeAI } = require("@google/generative-ai");

const expireTime = 1 * 60 * 60 * 1000; // 1 hour
const port = process.env.PORT || 3000;
const LIVE_DOMAIN = process.env.LIVE_DOMAIN || `http://localhost:${port}`;

// MongoDB Configuration
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_db = process.env.MONGODB_DB;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// Initialize Gemini only if API key is present
let google_gemini, geminiModel;
if (process.env.GEMINI_API_KEY) {
  google_gemini = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  geminiModel = google_gemini.getGenerativeModel({ model: "gemini-1.5-flash" });
} else {
  console.warn("GEMINI_API_KEY not found. AI features will be disabled.");
}

// Database Connection (ensure this is properly initialized)
var { database } = require("./databaseConnection"); // Assuming this file exports 'database'

// Multer setup for file uploads
const upload = multer({
  storage: multer.memoryStorage(), // Store files in memory for processing with Sharp
  limits: { filesize: 5 * 1024 * 1024 }, // 5MB limit
});

// Collections
const userCollection = database.db(mongodb_db).collection("users");
const postingCollection = database.db(mongodb_db).collection("posting");
const chatMessageCollection = database.db(mongodb_db).collection("chatMessages");
const transactionCollection = database.db(mongodb_db).collection("transactions");

// Session Store
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`, // Ensure this is your sessions DB
  crypto: {
    secret: mongodb_session_secret,
  },
});

// Session Middleware
const sessionMiddleware = session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true,
  cookie: { maxAge: expireTime },
});
app.use(sessionMiddleware);

// Share session middleware with Socket.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

// Stripe Webhook (Place before express.json() for raw body)
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["stripe-signature"];
      let event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET
      );

      if (event.type === "checkout.session.completed") {
        const sessionData = event.data.object; // Renamed to avoid conflict with 'session' middleware
        await transactionCollection.insertOne({
          buyerId: new ObjectId(sessionData.metadata.buyerId),
          sellerId: new ObjectId(sessionData.metadata.sellerId),
          transactionId: sessionData.payment_intent,
          amount: sessionData.amount_total / 100,
          currency: sessionData.currency,
          items: JSON.parse(sessionData.metadata.cartItems || "[]"),
          createdAt: new Date(sessionData.created * 1000),
        });
        console.log("Transaction recorded for checkout session:", sessionData.id);
      }
      res.sendStatus(200);
    } catch (err) {
      console.error("Error in Stripe webhook:", err.message);
      res.status(400).send(`Webhook Error: ${err.message}`);
    }
  }
);

// General Middlewares
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + "/public"));
app.set("view engine", "ejs");

// Middleware to pass session to all EJS templates
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// --- ROUTES ---

app.get("/", async (req, res) => {
  if (req.session.authenticated) {
    if (req.session.role === "seller") {
      const docs = await postingCollection
        .find({ sellerId: new ObjectId(req.session.userId) })
        .sort({ createdAt: -1 })
        .toArray();
      const postings = docs.map((doc) => ({
        _id: doc._id.toString(),
        produce: doc.produce,
        quantity: doc.quantity,
        price: doc.price,
        description: doc.description,
        createdAt: doc.createdAt,
        imageSrc: doc.image?.data ? `data:${doc.image.contentType};base64,${doc.image.data.toString("base64")}` : "/img/placeholder-large.png",
        thumbSrc: doc.thumbnail?.data ? `data:${doc.thumbnail.contentType};base64,${doc.thumbnail.data.toString("base64")}` : "/img/placeholder-thumb.png",
      }));
      res.render("sellerHome", {
        title: "My Postings",
        postings: postings,
        mapboxToken: process.env.MAPBOX_API_TOKEN,
        userFirstName: req.session.firstName,
      });
    } else if (req.session.role === "buyer") {
      const categories = await postingCollection.distinct("category");
      const selectedCategory = req.query.category || "";
      const selectedLanguage = req.query.language || "";
      let docs = await postingCollection.find({}).sort({ createdAt: -1 }).toArray();
      const sellerMap = await userCollection.find({ role: "seller" }).toArray()
        .then(users => users.reduce((map, u) => (map[u._id.toString()] = u.languages || [], map), {}));

      if (selectedCategory) docs = docs.filter(doc => doc.category === selectedCategory);
      if (selectedLanguage) docs = docs.filter(doc => (sellerMap[doc.sellerId?.toString()] || []).includes(selectedLanguage));

      const postings = docs.map((doc) => ({
        _id: doc._id.toString(),
        produce: doc.produce,
        quantity: doc.quantity,
        price: doc.price,
        description: doc.description,
        createdAt: doc.createdAt,
        imageSrc: doc.image?.data ? `data:${doc.image.contentType};base64,${doc.image.data.toString("base64")}` : "/img/placeholder-large.png",
        thumbSrc: doc.thumbnail?.data ? `data:${doc.thumbnail.contentType};base64,${doc.thumbnail.data.toString("base64")}` : "/img/placeholder-thumb.png",
      }));
      res.render("buyerHome", {
        title: "Buyer Home Page",
        mapboxToken: process.env.MAPBOX_API_TOKEN,
        postings: postings,
        categories: categories,
        selectedCategory: selectedCategory,
        selectedLanguage: selectedLanguage,
        languages: ['English', '中文', 'Español', 'Français', '한국어', 'Punjabi', 'Tiếng Việt', 'Tagalog'], // Consider making dynamic
        userFirstName: req.session.firstName,
      });
    } else {
      res.redirect("/login");
    }
  } else {
    res.render("landing", { title: "Landing" });
  }
});

app.post("/api/gemini", async (req, res) => {
  if (!geminiModel) return res.status(503).json({ error: "AI service is currently unavailable." });
  try {
    const prompt = req.body.prompt;
    if (!prompt) return res.status(400).json({ error: "Missing prompt" });
    const result = await geminiModel.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    return res.json({ text });
  } catch (err) {
    console.error("Gemini error:", err);
    res.status(500).json({ error: "Gemini API call failed." });
  }
});

app.get("/signup", (req, res) => {
  res.render("signup", { title: "Sign Up", mapboxToken: process.env.MAPBOX_API_TOKEN });
});

app.get("/login", (req, res) => {
  const error = req.session.error;
  delete req.session.error;
  res.render("login", { title: "Log in", error: error });
});

app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(), // Consider increasing max password length
  });
  const validationResult = schema.validate({ email, password }, { abortEarly: false });
  if (validationResult.error) {
    req.session.error = validationResult.error.details.map(d => d.message).join(" ");
    return res.redirect("/login");
  }
  try {
    const user = await userCollection.findOne({ email: email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      req.session.error = "Invalid email or password.";
      return res.redirect("/login");
    }
    req.session.authenticated = true;
    req.session.email = user.email;
    req.session.firstName = user.firstName;
    req.session.lastName = user.lastName;
    req.session.role = user.role;
    req.session.userId = user._id.toString();
    req.session.cookie.maxAge = expireTime;
    console.log("Login successful for:", user.email);
    return res.redirect("/");
  } catch (error) {
    console.error("Login error:", error);
    req.session.error = "An error occurred during login.";
    return res.redirect("/login");
  }
});

app.post("/signupSubmit", async (req, res) => {
  const { firstName, lastName, email, password, role, "address address-search": address, city, province, postalCode } = req.body;
  const schema = Joi.object({
    firstName: Joi.string().alphanum().min(1).max(50).required(),
    lastName: Joi.string().alphanum().min(1).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(100).required(),
    role: Joi.string().valid("buyer", "seller").required(),
    "address address-search": Joi.string().allow('').optional(),
    city: Joi.string().allow('').optional(),
    province: Joi.string().allow('').optional(),
    postalCode: Joi.string().allow('').optional(),
  });

  const { error: validationError } = schema.validate(req.body, { abortEarly: false });
  if (validationError) return res.status(400).send(`${validationError.details.map(d => d.message).join("<br>")} <a href="/signup">Try again</a>`);

  if (role === "seller" && (!address || !city || !province || !postalCode)) {
      return res.status(400).send(`Address, City, Province, and Postal Code are required for sellers. <a href="/signup">Try again</a>`);
  }

  try {
    const emailExists = await userCollection.findOne({ email });
    if (emailExists) return res.status(400).send('Email already registered. <a href="/login">Login</a> or <a href="/signup">try another email</a>.');

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUserDocument = {
      firstName, lastName, email, password: hashedPassword, role,
      languages: role === "seller" ? [] : undefined,
      createdAt: new Date(),
      // Default profile image can be set here if desired, or handled on display
      // profilePictureUrl: '/img/default-pfp.png'
    };
    if (role === "seller") newUserDocument.address = { address, city, province, postalCode };

    const result = await userCollection.insertOne(newUserDocument);
    const newUserId = result.insertedId;

    req.session.authenticated = true;
    req.session.firstName = firstName;
    req.session.lastName = lastName;
    req.session.email = email;
    req.session.role = role;
    req.session.userId = newUserId.toString();
    req.session.cookie.maxAge = expireTime;
    console.log("Signup successful for:", email);

    if (role === "seller") {
      try {
        const account = await stripe.accounts.create({
          type: "express", email: email, business_type: "individual",
          capabilities: { transfers: { requested: true } },
        });
        await userCollection.updateOne({ _id: newUserId }, { $set: { stripeAccountId: account.id } });
        return res.redirect("/languages");
      } catch (stripeError) {
        console.error("Stripe account creation/update error:", stripeError);
        // Potentially redirect to a page explaining the Stripe issue or just proceed to "/"
        // For now, letting it fall through to the general redirect
      }
    }
    return res.redirect("/");
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(500).send("Error creating account. <a href='/signup'>Try again</a>");
  }
});

app.get("/languages", (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") return res.redirect("/");
  res.render("languages", { title: "Select Languages" });
});

app.post("/languagesSubmit", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") return res.redirect("/");
  let languages = req.body.languages || [];
  if (!Array.isArray(languages)) languages = [languages]; // Ensure it's an array
  try {
    await userCollection.updateOne({ _id: new ObjectId(req.session.userId) }, { $set: { languages: languages } });
    console.log(`Languages updated for user ${req.session.userId}:`, languages);
    return res.redirect("/");
  } catch (error) {
    console.error("Error updating languages:", error);
    return res.status(500).send("Error updating languages. <a href='/languages'>Try again</a>");
  }
});

app.get("/logout", (req, res) => {
  const userEmail = req.session.email;
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
      return res.status(500).send("Could not log out.");
    }
    console.log("User logged out:", userEmail || "Unknown user");
    return res.redirect("/");
  });
});

app.get("/createPost", (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") return res.redirect("/login");
  res.render("createPost", { title: "Create Post", listing: null });
});

app.post("/createPost", upload.single("image"), async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") return res.status(403).redirect("/login");
  if (!req.file) return res.status(400).send("No image uploaded. <a href='/createPost'>Try again</a>");

  const { category, produce, quantity, price, description, location, latitude, longitude } = req.body;
  if (!produce || !quantity || !price) return res.status(400).send("Missing required fields (produce, quantity, price). <a href='/createPost'>Try again</a>");

  try {
    const fullBuffer = await sharp(req.file.buffer).resize({ width: 1080, withoutEnlargement: true }).jpeg({ quality: 80 }).toBuffer();
    const thumbBuffer = await sharp(req.file.buffer).resize({ width: 400, withoutEnlargement: true }).jpeg({ quality: 70 }).toBuffer();

    const newPosting = {
      category, produce,
      quantity: parseInt(quantity, 10),
      price: parseFloat(price),
      description,
      image: { data: fullBuffer, contentType: "image/jpeg" },
      thumbnail: { data: thumbBuffer, contentType: "image/jpeg" },
      sellerId: new ObjectId(req.session.userId),
      createdAt: new Date(),
      location: location || null,
    };
    if (latitude && longitude && !isNaN(parseFloat(latitude)) && !isNaN(parseFloat(longitude))) {
      newPosting.coordinates = { latitude: parseFloat(latitude), longitude: parseFloat(longitude) };
    }
    await postingCollection.insertOne(newPosting);
    console.log("New post created by:", req.session.email);
    return res.redirect("/");
  } catch (error) {
    console.error("Error creating post:", error);
    return res.status(500).send("Error processing your post. <a href='/createPost'>Try again</a>");
  }
});

app.get("/post/:id/edit", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") return res.redirect("/login");
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Invalid post ID");

  const doc = await postingCollection.findOne({ _id: new ObjectId(id) });
  if (!doc || doc.sellerId.toString() !== req.session.userId) return res.status(404).send("Post not found or permission denied.");

  const currentPost = {
    id: doc._id.toString(), category: doc.category, produce: doc.produce, quantity: doc.quantity,
    price: doc.price, description: doc.description, location: doc.location || "",
    latitude: doc.coordinates?.latitude || "", longitude: doc.coordinates?.longitude || "",
    imageUrl: doc.image?.data ? `data:${doc.image.contentType};base64,${doc.image.data.toString("base64")}` : "/img/placeholder-large.png",
  };
  res.render("editPost", { title: "Edit Post", currentPost });
});

app.post("/post/:id/edit", upload.single("image"), async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") return res.redirect("/login");
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Invalid post ID");

  const { category, produce, quantity, price, description, location, latitude, longitude } = req.body;
  const updateDoc = { $set: {
      category, produce, quantity: parseInt(quantity, 10), price: parseFloat(price),
      description, location: location || null,
  }};
  if (latitude && longitude && !isNaN(parseFloat(latitude)) && !isNaN(parseFloat(longitude))) {
    updateDoc.$set.coordinates = { latitude: parseFloat(latitude), longitude: parseFloat(longitude) };
  } else {
    updateDoc.$unset = { coordinates: "" }; // Remove coordinates if not provided or invalid
  }
  if (req.file) {
    const fullBuffer = await sharp(req.file.buffer).resize({ width: 1080, withoutEnlargement: true }).jpeg({ quality: 80 }).toBuffer();
    const thumbBuffer = await sharp(req.file.buffer).resize({ width: 400, withoutEnlargement: true }).jpeg({ quality: 70 }).toBuffer();
    updateDoc.$set.image = { data: fullBuffer, contentType: "image/jpeg" };
    updateDoc.$set.thumbnail = { data: thumbBuffer, contentType: "image/jpeg" };
  }
  const result = await postingCollection.updateOne({ _id: new ObjectId(id), sellerId: new ObjectId(req.session.userId) }, updateDoc);
  if (result.matchedCount === 0) return res.status(403).send("Update failed: Post not found or permission denied.");
  res.redirect("/");
});

app.post("/post/:id/delete", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") return res.redirect("/login");
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Invalid post ID");
  try {
    const result = await postingCollection.deleteOne({ _id: new ObjectId(id), sellerId: new ObjectId(req.session.userId) });
    if (result.deletedCount === 0) return res.status(403).send("Delete failed: Post not found or permission denied.");
    res.redirect("/");
  } catch (err) {
    console.error("Error deleting post:", err);
    res.status(500).send("Server error while deleting post");
  }
});


// --- CHAT ROUTES ---
// GET /chat (Main chat page for a specific conversation)
app.get("/chat", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  const currentUserId = req.session.userId; // String
  const otherUserIdString = req.query.with; // String

  if (!otherUserIdString || !ObjectId.isValid(otherUserIdString) || currentUserId === otherUserIdString) {
    return res.status(400).render("errorPage", { title: "Chat Error", errorMessage: "Invalid chat parameters." });
  }
  try {
    const otherUser = await userCollection.findOne(
      { _id: new ObjectId(otherUserIdString) },
      { projection: { firstName: 1, lastName: 1 } }
    );
    if (!otherUser) {
      return res.status(404).render("errorPage", { title: "Chat Error", errorMessage: "Chat partner not found." });
    }

    const ids = [currentUserId, otherUserIdString].sort(); // Sort to ensure chatId is always the same
    const chatId = ids.join("-");

    res.render("chat", { // Renders chat.ejs
      title: `Chat with ${otherUser.firstName || "User"}`,
      currentUserId: currentUserId,
      currentUserFirstName: req.session.firstName,
      otherUserId: otherUserIdString,
      otherUserName: `${otherUser.firstName || ""} ${otherUser.lastName || ""}`.trim(),
      chatId: chatId, // Pass the generated chatId to the client
    });
  } catch (error) {
    console.error("GET /chat error:", error);
    res.status(500).render("errorPage", { title: "Server Error", errorMessage: "Error loading chat." });
  }
});

// API to fetch messages for a given chat
app.get("/api/chat/:chatId/messages", async (req, res) => {
  if (!req.session.authenticated) return res.status(401).json({ error: "Unauthorized" });
  try {
    const { chatId } = req.params;
    // Validate that the current user is part of this chat
    const [user1Id, user2Id] = chatId.split("-");
    if (req.session.userId !== user1Id && req.session.userId !== user2Id) {
      return res.status(403).json({ error: "Forbidden: You are not part of this chat." });
    }

    const messagesFromDb = await chatMessageCollection.find({ chatId }).sort({ timestamp: 1 }).toArray();
    const messages = messagesFromDb.map((msg) => ({
      ...msg,
      _id: msg._id.toString(),
      senderId: msg.senderId.toString(),
      receiverId: msg.receiverId.toString(),
      ...(msg.messageType === "image" && msg.image?.data && {
        imageDataUri: `data:${msg.image.contentType};base64,${msg.image.data.toString("base64")}`,
      }),
    }));
    res.json(messages);
  } catch (error) {
    console.error("Error fetching chat messages:", error);
    res.status(500).json({ error: "Server error fetching messages." });
  }
});

// API to post a new text message
app.post("/api/chat/messages", async (req, res) => {
  if (!req.session.authenticated) return res.status(401).json({ error: "Unauthorized" });
  try {
    const { chatId, senderId, receiverId, messageText } = req.body;
    if (senderId !== req.session.userId) return res.status(403).json({ error: "Mismatched sender." });
    if (!chatId || !receiverId || !messageText || !messageText.trim()) return res.status(400).json({ error: "Missing or invalid fields." });

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
      _id: result.insertedId.toString(),
      chatId: newMessageDocument.chatId,
      senderId: senderId,
      receiverId: receiverId,
      messageText: newMessageDocument.messageText,
      messageType: "text",
      timestamp: newMessageDocument.timestamp,
    };
    io.to(chatId).emit("newMessage", savedMessage); // Broadcast to all clients in the room
    res.status(201).json(savedMessage);
  } catch (error) {
    console.error("Error sending chat message:", error);
    res.status(500).json({ error: "Server error sending message." });
  }
});

// API to post a new image message
app.post("/api/chat/messages/image", upload.single("chatImage"), async (req, res) => {
  if (!req.session.authenticated) return res.status(401).json({ error: "Unauthorized" });
  try {
    const { chatId, senderId, receiverId, caption } = req.body;
    if (!req.file) return res.status(400).json({ error: "No image file uploaded." });
    if (senderId !== req.session.userId) return res.status(403).json({ error: "Mismatched sender." });
    if (!chatId || !receiverId) return res.status(400).json({ error: "Missing chat ID or receiver ID." });

    const imageBuffer = await sharp(req.file.buffer).resize({ width: 800, withoutEnlargement: true }).jpeg({ quality: 75 }).toBuffer();
    const newMessageDocument = {
      chatId,
      senderId: new ObjectId(senderId),
      receiverId: new ObjectId(receiverId),
      messageText: caption || "",
      image: { data: imageBuffer, contentType: "image/jpeg" },
      messageType: "image",
      timestamp: new Date(),
    };
    const result = await chatMessageCollection.insertOne(newMessageDocument);
    const savedMessage = {
      _id: result.insertedId.toString(),
      chatId: newMessageDocument.chatId,
      senderId: senderId,
      receiverId: receiverId,
      messageType: "image",
      timestamp: newMessageDocument.timestamp,
      messageText: newMessageDocument.messageText,
      imageDataUri: `data:image/jpeg;base64,${imageBuffer.toString("base64")}`,
    };
    io.to(chatId).emit("newMessage", savedMessage); // Broadcast to all clients in the room
    res.status(201).json(savedMessage);
  } catch (error) {
    console.error("Error sending image message:", error);
    res.status(500).json({ error: "Server error sending image." });
  }
});


app.get("/viewpage", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  const postIdString = req.query.postId;
  if (!postIdString || !ObjectId.isValid(postIdString)) return res.status(400).render("errorPage", { title: "Error", errorMessage: "Invalid post ID." });

  try {
    const post = await postingCollection.findOne({ _id: new ObjectId(postIdString) });
    if (!post) return res.status(404).render("404", { title: "Post Not Found" });

    let sellerDetails = null;
    if (post.sellerId && ObjectId.isValid(post.sellerId)) {
      sellerDetails = await userCollection.findOne(
        { _id: new ObjectId(post.sellerId) },
        { projection: { firstName: 1, lastName: 1, image: 1, location: 1, address: 1, _id: 1, coordinates: 1 } }
      );
    }
    const sellerImage = { imageUrl: sellerDetails?.image?.data ? `data:${sellerDetails.image.contentType};base64,${sellerDetails.image.data.toString("base64")}` : "/img/placeholder-large.png" };

    const postForTemplate = {
      _id: post._id.toString(), produce: post.produce, quantity: post.quantity, price: post.price,
      description: post.description, createdAt: post.createdAt,
      imageSrc: post.image?.data ? `data:${post.image.contentType};base64,${post.image.data.toString("base64")}` : "/img/placeholder-large.png",
      location: post.location, coordinates: post.coordinates,
      seller: sellerDetails, // Contains seller's full details or null
    };
    res.render("viewpage", { title: `${post.produce || "View Post"}`, post: postForTemplate, mapboxToken: process.env.MAPBOX_API_TOKEN, sellerImage });
  } catch (error) {
    console.error("Error fetching post for viewpage:", error);
    res.status(500).render("errorPage", { title: "Server Error", errorMessage: "Could not load post details." });
  }
});

app.get("/cart", (req, res) => {
  if (req.session.authenticated && req.session.role === "buyer") {
    res.render("cart", { title: "Cart" });
  } else {
    res.redirect("/");
  }
});

app.post("/checkout", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "buyer") return res.status(403).json({ error: "Unauthorized" });

  const { sellerId, cartItems } = req.body;
  if (!sellerId || !ObjectId.isValid(sellerId)) return res.status(400).json({ error: "Invalid seller ID" });
  if (!cartItems || !Array.isArray(cartItems) || cartItems.length === 0) return res.status(400).json({ error: "Invalid cart items" });

  try {
    const seller = await userCollection.findOne({ _id: new ObjectId(sellerId) });
    if (!seller || !seller.stripeAccountId) return res.status(400).json({ error: "Seller not configured for payments or not found" });

    const line_items = cartItems.map((item) => {
      const parsedPrice = parseFloat(item.price);
      const parsedQuantity = parseInt(item.quantity, 10);
      if (isNaN(parsedPrice) || parsedPrice <= 0) throw new Error(`Invalid price for item "${item.produce}"`);
      if (isNaN(parsedQuantity) || parsedQuantity <= 0) throw new Error(`Invalid quantity for item "${item.produce}"`);
      const unitAmount = Math.round(parsedPrice * 100); // Price in cents
      let productImages = [];
      // Only include image if it's a public URL, not a data URI
      if (item.imageSrc && !item.imageSrc.startsWith("data:")) productImages.push(item.imageSrc);

      return {
        price_data: {
          currency: "cad", // Or your store's currency
          product_data: { name: item.produce, ...(productImages.length > 0 && { images: productImages }) },
          unit_amount: unitAmount,
        },
        quantity: parsedQuantity,
      };
    });

    const subtotal = line_items.reduce((sum, item) => sum + item.price_data.unit_amount * item.quantity, 0);
    if (subtotal === 0 && line_items.length > 0) return res.status(400).json({ error: "Cart total is zero." });
    const application_fee_amount = Math.max(0, Math.min(subtotal, Math.round(subtotal * 0.05))); // 5% fee, capped

    const checkoutSessionPayload = {
      payment_method_types: ["card"], line_items, mode: "payment",
      payment_intent_data: { application_fee_amount, transfer_data: { destination: seller.stripeAccountId } },
      success_url: `${LIVE_DOMAIN}/?checkout=success`,
      cancel_url: `${LIVE_DOMAIN}/cart?checkout=cancelled`,
      metadata: {
        buyerId: req.session.userId, sellerId,
        cartItems: JSON.stringify(cartItems.map(i => ({ produce: i.produce, quantity: i.quantity, price: i.price }))),
      },
    };
    const checkoutSession = await stripe.checkout.sessions.create(checkoutSessionPayload);
    res.json({ url: checkoutSession.url });
  } catch (error) {
    console.error("Stripe Checkout Error:", error.message, error); // Log full error
    res.status(500).json({ error: "Failed to create checkout session", stripeError: error.message });
  }
});

app.get("/profile", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/");
  const user = await userCollection.findOne({ _id: new ObjectId(req.session.userId) }, { projection: { password: 0 } });
  if (!user) { req.session.destroy(); return res.redirect("/"); } // Handle case where user deleted but session exists
  const userImage = { imageUrl: user.image?.data ? `data:${user.image.contentType};base64,${user.image.data.toString("base64")}` : "/img/farmerpfp.png" };
  const view = user.role === "seller" ? "sellerProfile" : "buyerProfile";
  res.render(view, { title: "User Profile", user, mapboxToken: process.env.MAPBOX_API_TOKEN, userImage });
});

app.post("/profile", upload.single("image"), async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/");
  const user = await userCollection.findOne({ _id: new ObjectId(req.session.userId) });
  if (!user) { req.session.destroy(); return res.redirect("/"); }

  let schemaDefinition = {
    firstName: Joi.string().min(1).max(50).required(),
    lastName: Joi.string().min(1).max(50).required(),
    email: Joi.string().email().required(),
  };
  if (user.role === "seller") {
    schemaDefinition["address address-search"] = Joi.string().min(1).max(100).required();
    schemaDefinition.city = Joi.string().min(1).max(50).required();
    schemaDefinition.province = Joi.string().min(1).max(50).required();
    // Canadian postal code: A1A 1A1 or A1A1A1
    schemaDefinition.postalCode = Joi.string().pattern(/^[A-Za-z]\d[A-Za-z][ -]?\d[A-Za-z]\d$/).required().messages({'string.pattern.base': 'Postal code must be in a valid Canadian format (e.g., A1A 1A1).'});
  }
  const schema = Joi.object(schemaDefinition).unknown(true);

  const { error: validationError, value } = schema.validate(req.body, { abortEarly: false });
  if (validationError) return res.status(400).send(validationError.details.map(d => d.message).join("; "));

  const existingEmailUser = await userCollection.findOne({ email: value.email });
  if (existingEmailUser && existingEmailUser._id.toString() !== req.session.userId) return res.status(400).send("Email already in use.");

  const updates = { firstName: value.firstName, lastName: value.lastName, email: value.email };
  if (req.file) {
    // For profile pictures, often a square crop is desired.
    const imageBuffer = await sharp(req.file.buffer)
      .resize({ width: 300, height: 300, fit: sharp.fit.cover, withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toBuffer();
    updates.image = { data: imageBuffer, contentType: "image/jpeg" };
  }
  if (user.role === "seller") {
    updates.address = {
      address: value["address address-search"], city: value.city,
      province: value.province, postalCode: value.postalCode.toUpperCase().replace(/\s/g, ''), // Standardize
    };
    // If seller address changes, consider geocoding and updating user.coordinates
  }
  await userCollection.updateOne({ _id: new ObjectId(req.session.userId) }, { $set: updates });
  // Update session with new details if they changed
  req.session.firstName = updates.firstName;
  req.session.lastName = updates.lastName;
  req.session.email = updates.email;
  res.redirect("/profile");
});

app.get("/contacts", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  const currentUserIdString = req.session.userId;
  const currentUserId = new ObjectId(currentUserIdString);

  try {
    // Get all unique user IDs this user has chatted with
    const distinctSenderIds = await chatMessageCollection.distinct("senderId", { receiverId: currentUserId });
    const distinctReceiverIds = await chatMessageCollection.distinct("receiverId", { senderId: currentUserId });

    // Combine, remove self, and convert to ObjectId
    const allInteractedUserIds = [...new Set([...distinctSenderIds, ...distinctReceiverIds])]
      .filter(id => id.toString() !== currentUserIdString) // Exclude self
      .map(id => new ObjectId(id));

    let contacts = [];
    if (allInteractedUserIds.length > 0) {
      contacts = await userCollection
        .find({ _id: { $in: allInteractedUserIds } }, { projection: { firstName: 1, lastName: 1, image: 1 } })
        .map(user => ({
          ...user,
          _id: user._id.toString(),
          profilePictureUrl: user.image?.data ? `data:${user.image.contentType};base64,${user.image.data.toString("base64")}` : '/img/farmerpfp.png' // Default or dynamic
        }))
        .toArray();
    }

    res.render("contacts", {
      title: "My Messages",
      contacts: contacts,
      currentUserId: currentUserIdString,
      userRole: req.session.role,
    });
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).render("errorPage", { title: "Error", errorMessage: "Could not load your messages." });
  }
});

app.get("/map", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  // Fetch sellers with address or coordinates for map display
  const sellers = await userCollection.find({ role: "seller", $or: [{ address: { $exists: true, $ne: null } }, { coordinates: { $exists: true, $ne: null } }] }).toArray();
  res.render("map", { title: "Map", mapboxToken: process.env.MAPBOX_API_TOKEN, sellers: sellers });
});


// --- SOCKET.IO REAL-TIME LOGIC ---
io.on("connection", (socket) => {
  const session = socket.request.session; // Access session data via middleware
  if (!session || !session.authenticated) {
    console.log(`Socket connection attempt by unauthenticated user. Disconnecting socket ${socket.id}`);
    socket.disconnect(true);
    return;
  }

  console.log(`User ${session.firstName || 'Unknown'} (${session.userId}) connected with socket ${socket.id}`);

  socket.on("joinChat", (chatId) => {
    if (chatId && typeof chatId === "string" && chatId.includes("-")) {
      // Basic validation for chatId format, e.g., "userId1-userId2"
      socket.join(chatId);
      console.log(`Socket ${socket.id} (User: ${session.userId}) joined chat room: ${chatId}`);
    } else {
      console.warn(`Socket ${socket.id} (User: ${session.userId}) tried to join invalid chat room: ${chatId}`);
    }
  });

  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.id} (User: ${session.firstName || "Unknown"})`);
    // Socket.IO automatically handles leaving rooms on disconnect
  });
});


// --- 404 AND ERROR HANDLER ---
app.use(async (req, res, next) => {
  let userRole = null;
  if (req.session && req.session.authenticated && req.session.userId) {
      try {
          const user = await userCollection.findOne(
              { _id: new ObjectId(req.session.userId) },
              { projection: { role: 1 } }
          );
          userRole = user ? user.role : null;
      } catch (dbError) {
          console.error("Error fetching user role for 404 page:", dbError);
      }
  }
  res.status(404).render("404", { title: "Page Not Found", user: { role: userRole } });
});


app.use((err, req, res, next) => {
  console.error("Global error for URL:", req.originalUrl, "\n", err.stack);
  if (!res.headersSent) {
    res.status(err.status || 500).render("errorPage", {
      title: "Server Error",
      errorMessage: err.message || "An unexpected server error occurred.",
    });
  } else {
    next(err); // Delegate to default Express error handler if headers already sent
  }
});

// Start the server
server.listen(port, () => {
  console.log(`Server with Socket.IO is running on port ${port}`);
  console.log(`Access at: ${LIVE_DOMAIN}`);
});