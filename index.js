require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const multer = require("multer");
const sharp = require("sharp");
const Joi = require("joi");
const { ObjectId } = require("mongodb");
const http = require("http");
const { Server } = require("socket.io");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const LIVE_DOMAIN = process.env.LIVE_DOMAIN || "http://localhost:3000";

const saltRounds = 12;
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

const { GoogleGenerativeAI } = require("@google/generative-ai");

const expireTime = 1 * 60 * 60 * 1000;
const port = process.env.PORT || 3000;

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
  geminiModel = google_gemini.getGenerativeModel({ model: "gemini-1.5-flash" }); // Updated model
} else {
  console.warn("GEMINI_API_KEY not found. AI features will be disabled.");
}

var { database } = require("./databaseConnection");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { filesize: 5 * 1024 * 1024 },
});

const userCollection = database.db(mongodb_db).collection("users");
const postingCollection = database.db(mongodb_db).collection("posting");
const chatMessageCollection = database
  .db(mongodb_db)
  .collection("chatMessages");
const transactionCollection = database
  .db(mongodb_db)
  .collection("transactions");

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

const sessionMiddleware = session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true,
  cookie: { maxAge: expireTime },
});
app.use(sessionMiddleware);

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

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
        const session = event.data.object;
        await transactionCollection.insertOne({
          buyerId: new ObjectId(session.metadata.buyerId),
          sellerId: new ObjectId(session.metadata.sellerId),
          transactionId: session.payment_intent,
          amount: session.amount_total / 100,
          currency: session.currency,
          items: JSON.parse(session.metadata.cartItems || "[]"), // Store items
          createdAt: new Date(session.created * 1000),
        });
        console.log("Transaction recorded for checkout session:", session.id);
      }
      res.sendStatus(200);
    } catch (err) {
      console.error("Error in Stripe webhook:", err.message);
      res.status(400).send(`Webhook Error: ${err.message}`);
    }
  }
);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + "/public"));
app.set("view engine", "ejs");

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
        _id: doc._id.toString(), // Ensure _id is passed for edit/delete links
        produce: doc.produce,
        quantity: doc.quantity,
        price: doc.price,
        description: doc.description,
        createdAt: doc.createdAt,
        imageSrc:
          doc.image && doc.image.data
            ? `data:${doc.image.contentType};base64,${doc.image.data.toString(
              "base64"
            )}`
            : "/img/placeholder-large.png",
        thumbSrc:
          doc.thumbnail && doc.thumbnail.data
            ? `data:${doc.thumbnail.contentType
            };base64,${doc.thumbnail.data.toString("base64")}`
            : "/img/placeholder-thumb.png",
      }));

      res.render("sellerHome", {
        title: "My Postings",
        postings: postings,
        mapboxToken: process.env.MAPBOX_API_TOKEN,
      });
    } else if (req.session.role === "buyer") {
      // 1) Load all distinct categories for the dropdown
      const categories = await postingCollection.distinct("category");

      // 2) Read the selected category from ?category=… (defaults to “all”)
      const selectedCategory = req.query.category || "";

      let docs = await postingCollection
        .find({}) // Find all posts for buyers
        .sort({ createdAt: -1 })
        .toArray();
      if (selectedCategory) {
        docs = docs.filter((doc) => doc.category === selectedCategory);
      }

      // Map the selected posts to the view
      const postings = docs.map((doc) => ({
        _id: doc._id.toString(),
        produce: doc.produce,
        quantity: doc.quantity,
        price: doc.price,
        description: doc.description,
        createdAt: doc.createdAt,
        imageSrc:
          doc.image && doc.image.data
            ? `data:${doc.image.contentType};base64,${doc.image.data.toString(
              "base64"
            )}`
            : "/img/placeholder-large.png",
        thumbSrc:
          doc.thumbnail && doc.thumbnail.data
            ? `data:${doc.thumbnail.contentType
            };base64,${doc.thumbnail.data.toString("base64")}`
            : "/img/placeholder-thumb.png",
      }));

      res.render("buyerHome", {
        title: "Buyer Home Page",
        mapboxToken: process.env.MAPBOX_API_TOKEN,
        postings: postings,
        categories: categories,
        selectedCategory: selectedCategory,
      });
    } else {
      res.redirect("/login");
    }
  } else {
    res.render("landing", { title: "Landing" });
  }
});

app.post("/api/gemini", async (req, res) => {
  if (!geminiModel) {
    return res
      .status(503)
      .json({ error: "AI service is currently unavailable." });
  }
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
  res.render("signup", {
    title: "Sign Up",
    mapboxToken: process.env.MAPBOX_API_TOKEN,
  });
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
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate(
    { email, password },
    { abortEarly: false }
  );
  if (validationResult.error) {
    const fields = validationResult.error.details.map((d) => d.context.key);
    const uniqueFields = Array.from(new Set(fields));
    const errorMessages = uniqueFields
      .map((f) => `${f} is invalid or missing.`)
      .join(" ");
    req.session.error = errorMessages;
    return res.redirect("/login");
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
      req.session.cookie.maxAge = expireTime;

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

app.post("/signupSubmit", async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    password,
    role,
    "address address-search": address,
    city,
    province,
    postalCode,
  } = req.body;
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
      .send(
        `${error.details
          .map((d) => d.message)
          .join("<br>")} <a href="/signup">Try again</a>`
      );
  }

  try {
    const emailExists = await userCollection.findOne({ email });
    if (emailExists) {
      return res
        .status(400)
        .send(
          'Email already registered. <a href="/login">Login</a> or <a href="/signup">try another email</a>.'
        );
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUserDocument = {
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role,
      languages: role === "seller" ? [] : undefined,
      createdAt: new Date(),
      // Add fields for profile picture, location, coordinates if desired at signup
      // profilePictureUrl: '/img/default-pfp.png', // Example default
      // location: '',
      // coordinates: null,
    };

    if (role === "seller") {
      newUserDocument.address = { address, city, province, postalCode };
    }

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
          type: "express",
          email: email,
          business_type: "individual",
          capabilities: { transfers: { requested: true } },
        });

        await userCollection.updateOne(
          { _id: newUserId },
          { $set: { stripeAccountId: account.id } }
        );
        return res.redirect("/languages"); // Or redirect to Stripe onboarding if needed
      } catch (stripeError) {
        console.error("Stripe account creation/update error:", stripeError);
        // Decide how to handle this - maybe let user proceed but log error
        // Or show an error and ask to retry seller setup later
      }
    }
    return res.redirect("/");
  } catch (error) {
    console.error("Signup error:", error);
    return res
      .status(500)
      .send("Error creating account. <a href='/signup'>Try again</a>");
  }
});

app.get("/languages", (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/");
  }
  res.render("languages", { title: "Select Languages" });
});

app.post("/languagesSubmit", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/");
  }
  let languages = req.body.languages;
  if (!languages) languages = [];
  else if (!Array.isArray(languages)) languages = [languages];

  try {
    await userCollection.updateOne(
      { _id: new ObjectId(req.session.userId) },
      { $set: { languages: languages } }
    );
    console.log(`Languages updated for user ${req.session.userId}:`, languages);
    return res.redirect("/");
  } catch (error) {
    console.error("Error updating languages:", error);
    return res
      .status(500)
      .send("Error updating languages. <a href='/languages'>Try again</a>");
  }
});

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

app.get("/createPost", (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.redirect("/login");
  }
  res.render("createPost", { title: "Create Post", listing: null });
});

app.post("/createPost", upload.single("image"), async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller") {
    return res.status(403).redirect("/login");
  }
  if (!req.file) {
    return res
      .status(400)
      .send("No image uploaded. <a href='/createPost'>Try again</a>");
  }

  const { category, produce, quantity, price, description, location, latitude, longitude } = req.body;
  // Basic validation for other fields (Joi could be used here too for more robustness)
  if (!produce || !quantity || !price) {
    return res
      .status(400)
      .send(
        "Missing required fields (produce, quantity, price). <a href='/createPost'>Try again</a>"
      );
  }

  try {
    const fullBuffer = await sharp(req.file.buffer).resize({ width: 1080, withoutEnlargement: true }).jpeg({ quality: 80 }).toBuffer();
    const thumbBuffer = await sharp(req.file.buffer).resize({ width: 400, withoutEnlargement: true }).jpeg({ quality: 70 }).toBuffer();

    // build your post object
    const newPosting = {
      category,
      produce,
      quantity: parseInt(quantity, 10),
      price: parseFloat(price),
      description,
      image: { data: fullBuffer, contentType: "image/jpeg" },
      thumbnail: { data: thumbBuffer, contentType: "image/jpeg" },
      sellerId: new ObjectId(req.session.userId),
      createdAt: new Date(),
      location: location || null,
    };
    // optional coordinates
    if (
      latitude && longitude &&
      !isNaN(parseFloat(latitude)) &&
      !isNaN(parseFloat(longitude))
    ) {
      newPosting.coordinates = {
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        longitude: parseFloat(longitude),
      };
    }

    // Add the new posting in the DB.
    postingCollection.insertOne(newPosting);

    console.log("New post created by:", req.session.email);
    return res.redirect("/");
  } catch (error) {
    console.error("Error creating post:", error);
    return res
      .status(500)
      .send("Error processing your post. <a href='/createPost'>Try again</a>");
  }
});

app.get("/post/:id/edit", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller")
    return res.redirect("/login");
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Invalid post ID");

  const doc = await postingCollection.findOne({ _id: new ObjectId(id) });
  if (!doc || doc.sellerId.toString() !== req.session.userId) {
    // Ensure seller owns the post
    return res
      .status(404)
      .send("Post not found or you do not have permission to edit it.");
  }

  const currentPost = {
    id: doc._id.toString(),
    category: doc.category,
    produce: doc.produce,
    quantity: doc.quantity,
    price: doc.price,
    description: doc.description,
    location: doc.location || "",
    latitude: doc.coordinates ? doc.coordinates.latitude : "",
    longitude: doc.coordinates ? doc.coordinates.longitude : "",
    imageUrl:
      doc.image && doc.image.data
        ? `data:${doc.image.contentType};base64,${doc.image.data.toString(
          "base64"
        )}`
        : "/img/placeholder-large.png",
  };
  res.render("editPost", { title: "Edit Post", currentPost });
});

app.post("/post/:id/edit", upload.single("image"), async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "seller")
    return res.redirect("/login");
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Invalid post ID");

  const { category, produce, quantity, price, description, location, latitude, longitude } = req.body;
  const updateDoc = {
    $set: {
      category,
      produce,
      quantity: parseInt(quantity, 10),
      price: parseFloat(price),
      description,
      location: location || null,
    },
  };

  if (
    latitude &&
    longitude &&
    !isNaN(parseFloat(latitude)) &&
    !isNaN(parseFloat(longitude))
  ) {
    updateDoc.$set.coordinates = {
      latitude: parseFloat(latitude),
      longitude: parseFloat(longitude),
    };
  } else {
    updateDoc.$unset = { coordinates: "" }; // Remove coordinates if not provided or invalid
  }

  if (req.file) {
    const fullBuffer = await sharp(req.file.buffer)
      .resize({ width: 1080, withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toBuffer();
    const thumbBuffer = await sharp(req.file.buffer)
      .resize({ width: 400, withoutEnlargement: true })
      .jpeg({ quality: 70 })
      .toBuffer();
    updateDoc.$set.image = { data: fullBuffer, contentType: "image/jpeg" };
    updateDoc.$set.thumbnail = { data: thumbBuffer, contentType: "image/jpeg" };
  }

  // Ensure seller can only update their own posts
  const result = await postingCollection.updateOne(
    { _id: new ObjectId(id), sellerId: new ObjectId(req.session.userId) },
    updateDoc
  );

  if (result.matchedCount === 0) {
    return res
      .status(403)
      .send(
        "Could not update post. It may not exist or you don't have permission."
      );
  }
  res.redirect("/");
});

// --- CHAT ROUTES (Simplified for brevity, assuming they are mostly working) ---
app.get("/chat", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  const currentUserId = req.session.userId;
  const otherUserIdString = req.query.with;

  if (
    !otherUserIdString ||
    !ObjectId.isValid(otherUserIdString) ||
    currentUserId === otherUserIdString
  ) {
    return res
      .status(400)
      .render("errorPage", {
        title: "Chat Error",
        errorMessage: "Invalid chat parameters.",
      });
  }
  try {
    const otherUser = await userCollection.findOne(
      { _id: new ObjectId(otherUserIdString) },
      { projection: { firstName: 1, lastName: 1 } }
    );
    if (!otherUser)
      return res
        .status(404)
        .render("errorPage", {
          title: "Chat Error",
          errorMessage: "Chat partner not found.",
        });

    const ids = [currentUserId, otherUserIdString].sort();
    const chatId = ids.join("-");
    res.render("chat", {
      title: `Chat with ${otherUser.firstName}`,
      currentUserId,
      currentUserFirstName: req.session.firstName,
      otherUserId: otherUserIdString,
      otherUserName: `${otherUser.firstName} ${otherUser.lastName || ""
        }`.trim(),
      chatId,
    });
  } catch (error) {
    console.error("GET /chat error:", error);
    res
      .status(500)
      .render("errorPage", {
        title: "Server Error",
        errorMessage: "Error loading chat.",
      });
  }
});

app.get("/api/chat/:chatId/messages", async (req, res) => {
  if (!req.session.authenticated)
    return res.status(401).json({ error: "Unauthorized" });
  try {
    const { chatId } = req.params;
    const [user1, user2] = chatId.split("-");
    if (user1 !== req.session.userId && user2 !== req.session.userId)
      return res.status(403).json({ error: "Forbidden" });

    const messagesFromDb = await chatMessageCollection
      .find({ chatId })
      .sort({ timestamp: 1 })
      .toArray();
    const messages = messagesFromDb.map((msg) => ({
      ...msg,
      _id: msg._id.toString(),
      senderId: msg.senderId.toString(),
      receiverId: msg.receiverId.toString(),
      ...(msg.messageType === "image" &&
        msg.image?.data && {
        imageDataUri: `data:${msg.image.contentType
          };base64,${msg.image.data.toString("base64")}`,
      }),
    }));
    res.json(messages);
  } catch (error) {
    console.error("Error fetching chat messages:", error);
    res.status(500).json({ error: "Server error fetching messages." });
  }
});

app.post("/api/chat/messages", async (req, res) => {
  if (!req.session.authenticated)
    return res.status(401).json({ error: "Unauthorized" });
  try {
    const { chatId, senderId, receiverId, messageText } = req.body;
    if (senderId !== req.session.userId)
      return res.status(403).json({ error: "Mismatched sender." });
    // Basic validation (add more as needed)
    if (!chatId || !receiverId || !messageText)
      return res.status(400).json({ error: "Missing fields." });

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
      senderId: senderId,
      receiverId: receiverId,
    };
    io.to(chatId).emit("newMessage", savedMessage);
    res.status(201).json(savedMessage);
  } catch (error) {
    console.error("Error sending chat message:", error);
    res.status(500).json({ error: "Server error sending message." });
  }
});

app.post(
  "/api/chat/messages/image",
  upload.single("chatImage"),
  async (req, res) => {
    if (!req.session.authenticated)
      return res.status(401).json({ error: "Unauthorized" });
    try {
      const { chatId, senderId, receiverId, caption } = req.body;
      if (!req.file)
        return res.status(400).json({ error: "No image file uploaded." });
      if (senderId !== req.session.userId)
        return res.status(403).json({ error: "Mismatched sender." });
      if (!chatId || !receiverId)
        return res.status(400).json({ error: "Missing fields." });

      const imageBuffer = await sharp(req.file.buffer)
        .resize({ width: 800, withoutEnlargement: true })
        .jpeg({ quality: 75 })
        .toBuffer();
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
        chatId,
        senderId,
        receiverId,
        messageType: "image",
        timestamp: newMessageDocument.timestamp,
        messageText: newMessageDocument.messageText,
        imageDataUri: `data:image/jpeg;base64,${imageBuffer.toString(
          "base64"
        )}`,
      };
      io.to(chatId).emit("newMessage", savedMessage);
      res.status(201).json(savedMessage);
    } catch (error) {
      console.error("Error sending image message:", error);
      res.status(500).json({ error: "Server error sending image." });
    }
  }
);

// --- VIEWPAGE, CART, CHECKOUT ---
app.get("/viewpage", async (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }

  const postIdString = req.query.postId;

  if (!postIdString || !ObjectId.isValid(postIdString)) {
    return res
      .status(400)
      .render("errorPage", {
        title: "Error",
        errorMessage: "Invalid or missing post ID.",
      });
  }

  try {
    const post = await postingCollection.findOne({
      _id: new ObjectId(postIdString),
    });
    if (!post) {
      return res.status(404).render("404", { title: "Post Not Found" });
    }

    let sellerDetails = null;
    if (post.sellerId && ObjectId.isValid(post.sellerId)) {
      sellerDetails = await userCollection.findOne(
        { _id: new ObjectId(post.sellerId) },
        {
          projection: {
            firstName: 1,
            lastName: 1,
            profilePictureUrl: 1,
            location: 1,
            address: 1,
            _id: 1 /* Need _id for chat link */,
          },
        }
      );
    }

    const postForTemplate = {
      _id: post._id.toString(),
      produce: post.produce,
      quantity: post.quantity,
      price: post.price,
      description: post.description,
      createdAt: post.createdAt,
      imageSrc:
        post.image && post.image.data
          ? `data:${post.image.contentType};base64,${post.image.data.toString(
            "base64"
          )}`
          : "/img/placeholder-large.png",
      location: post.location, // Item's specific location string
      coordinates: post.coordinates, // Item's specific coordinates
      seller: sellerDetails, // This will contain seller's _id, firstName, etc. or be null
    };

    res.render("viewpage", {
      title: `${post.produce || "View Post"}`,
      post: postForTemplate,
      mapboxToken: process.env.MAPBOX_API_TOKEN,
    });
  } catch (error) {
    console.error("Error fetching post for viewpage:", error);
    res
      .status(500)
      .render("errorPage", {
        title: "Server Error",
        errorMessage: "Could not load the post details.",
      });
  }
});

app.get("/cart", (req, res) => {
  if (req.session.authenticated && req.session.role === "buyer") {
    // Here you might fetch cart items from session or database if you persist them
    // For now, just rendering the page. Cart logic is client-side in this example.
    res.render("cart", { title: "Cart" });
  } else {
    res.redirect("/");
  }
});

app.post("/checkout", async (req, res) => {
  if (!req.session.authenticated || req.session.role !== "buyer") {
    console.log("Checkout attempt by unauthenticated or non-buyer user.");
    return res.status(403).json({ error: "Unauthorized" });
  }

  const { sellerId, cartItems } = req.body;

  console.log("--- /checkout ROUTE HIT ---");
  console.log("Timestamp:", new Date().toISOString());
  console.log("Session UserID (Buyer):", req.session.userId);
  console.log("Received sellerId:", sellerId);
  console.log("Received cartItems (raw):", JSON.stringify(cartItems, null, 2));

  if (!sellerId || !ObjectId.isValid(sellerId)) {
    // Added ObjectId validation for sellerId
    console.error("Validation Error: Invalid or missing sellerId.");
    return res.status(400).json({ error: "Invalid seller ID" });
  }
  if (!cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
    console.error("Validation Error: Invalid or missing cartItems.");
    return res.status(400).json({ error: "Invalid cart items" });
  }

  try {
    const seller = await userCollection.findOne({
      _id: new ObjectId(sellerId),
    });

    console.log(
      "Seller found in DB:",
      seller
        ? JSON.stringify({
          _id: seller._id,
          stripeAccountId: seller.stripeAccountId,
          firstName: seller.firstName,
        })
        : "null"
    );

    if (!seller || !seller.stripeAccountId) {
      console.error(
        `Error: Seller ${sellerId} not found or has no stripeAccountId. Seller data: ${JSON.stringify(
          seller
        )}`
      );
      return res
        .status(400)
        .json({ error: "Seller not configured for payments or not found" });
    }
    console.log("Using Seller Stripe Account ID:", seller.stripeAccountId);

    const line_items = cartItems.map((item) => {
      const parsedPrice = parseFloat(item.price);
      const parsedQuantity = parseInt(item.quantity, 10);

      if (isNaN(parsedPrice) || parsedPrice <= 0) {
        throw new Error(
          `Invalid price for item "${item.produce}": ${item.price}`
        );
      }
      if (isNaN(parsedQuantity) || parsedQuantity <= 0) {
        throw new Error(
          `Invalid quantity for item "${item.produce}": ${item.quantity}`
        );
      }

      const unitAmount = Math.round(parsedPrice * 100);
      if (unitAmount < 50) {
        // Stripe's typical minimum (e.g., $0.50 USD/CAD)
        console.warn(
          `Warning: Item "${item.produce}" has unit_amount ${unitAmount} cents, which might be below Stripe's minimum. This could cause issues.`
        );
      }

      // --- IMAGE HANDLING ---
      let productImages = [];
      if (item.imageSrc && !item.imageSrc.startsWith("data:")) {
        // If it's not a data URI, assume it's a public URL and pass it.
        productImages.push(item.imageSrc);
      } else if (item.imageSrc && item.imageSrc.startsWith("data:")) {
        console.warn(
          `Item "${item.produce}" has a data URI image. Stripe Checkout requires public URLs for images. Image will be omitted.`
        );
        // Do not add data URIs to productImages
      }
      // --- END IMAGE HANDLING ---

      return {
        price_data: {
          currency: "cad", // Ensure this matches your Stripe account's default or supported currencies
          product_data: {
            name: item.produce,
            ...(productImages.length > 0 && { images: productImages }), // Conditionally add images
          },
          unit_amount: unitAmount,
        },
        quantity: parsedQuantity,
      };
    });

    console.log(
      "Formatted line_items for Stripe:",
      JSON.stringify(line_items, null, 2)
    );

    const subtotal = line_items.reduce(
      (sum, item) => sum + item.price_data.unit_amount * item.quantity,
      0
    );
    // Application fee must be an integer. It also cannot exceed the total amount.
    const application_fee_amount = Math.max(
      0,
      Math.min(subtotal, Math.round(subtotal * 0.05))
    ); // 5% fee, ensure non-negative and not > subtotal

    console.log("Subtotal (cents):", subtotal);
    console.log("Application Fee Amount (cents):", application_fee_amount);

    if (subtotal === 0 && line_items.length > 0) {
      console.error(
        "Error: Cart subtotal is 0, cannot create payment session."
      );
      return res.status(400).json({ error: "Cart total is zero." });
    }

    const checkoutSessionPayload = {
      payment_method_types: ["card"],
      line_items,
      mode: "payment",
      payment_intent_data: {
        application_fee_amount: application_fee_amount,
        transfer_data: {
          destination: seller.stripeAccountId,
        },
      },
      success_url: `${LIVE_DOMAIN}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${LIVE_DOMAIN}/cart`,
      metadata: {
        buyerId: req.session.userId,
        sellerId: sellerId, // Already a string
        cartItems: JSON.stringify(
          cartItems.map((i) => ({
            produce: i.produce,
            quantity: i.quantity,
            price: i.price,
          }))
        ),
      },
    };

    console.log(
      "Final payload for Stripe checkoutSession.create:",
      JSON.stringify(checkoutSessionPayload, null, 2)
    );

    const checkoutSession = await stripe.checkout.sessions.create(
      checkoutSessionPayload
    );

    console.log(
      "Stripe Checkout Session created successfully, ID:",
      checkoutSession.id
    );
    res.json({ url: checkoutSession.url });
  } catch (error) {
    console.error("--- STRIPE CHECKOUT ERROR ---");
    console.error("Timestamp:", new Date().toISOString());
    console.error("Error Type:", error.type); // Stripe error type if available
    console.error("Error Code:", error.code); // Stripe error code if available
    console.error("Error Message:", error.message);
    console.error("Error Param:", error.param); // Parameter causing the issue
    console.error("Full Stripe Error Object:", JSON.stringify(error, null, 2)); // Log the whole error
    console.error("--- END STRIPE CHECKOUT ERROR ---");
    res
      .status(500)
      .json({
        error: "Failed to create checkout session",
        stripeError: error.message,
        stripeErrorCode: error.code,
      });
  }
});

// route for profile
app.get("/profile", async (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/");
  }

  // fetch all fields except password
  const user = await userCollection.findOne(
    { _id: new ObjectId(req.session.userId) },
    { projection: { password: 0 } }
  );

  const userImage = {
    imageUrl:
      user.image && user.image.data
        ? `data:${user.image.contentType};base64,${user.image.data.toString(
          "base64"
        )}`
        : "/img/placeholder-large.png"
  }

  // edge case: session exists but user corrupt/null
  if (!user) {
    req.session.destroy();
    return res.redirect("/");
  }

  const view = user.role === "seller" ? "sellerProfile" : "buyerProfile";

  res.render(view, {
    title: "User Profile Settings",
    user,
    mapboxToken: process.env.MAPBOX_API_TOKEN,
    userImage
  });
});

// handle profile edits
app.post("/profile", upload.single("image"), async (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/");
  }

  const {
    "address address-search": address,
    city,
    province,
    postalCode,
  } = req.body;

  const user = await userCollection.findOne({ _id: new ObjectId(req.session.userId) });

  let schema;

  // Validate incoming fields based on user
  if (user.role === "buyer") {
    // Buyer's only need to upate name and email
    schema = Joi.object({
      firstName: Joi.string().min(1).max(50).required(),
      lastName: Joi.string().min(1).max(50).required(),
      email: Joi.string().email().required()
    }).unknown(true);
  } else if (user.role === "seller") {
    // Seller's can also update address
    schema = Joi.object({
      firstName: Joi.string().min(1).max(50).required(),
      lastName: Joi.string().min(1).max(50).required(),
      email: Joi.string().email().required(),
      "address address-search": Joi.string().min(1).max(50).required(),
      city: Joi.string().min(1).max(50).required(),
      province: Joi.string().min(1).max(50).required(),
      postalCode: Joi.string().min(7).max(7).required(),
    }).unknown(true);
  }

  const { error, value } = schema.validate(req.body, { abortEarly: false });
  if (error) {
    const msgs = error.details.map((d) => d.message).join("; ");
    return res.status(400).send(msgs);
  }

  // ensure no one else is using this email
  const existing = await userCollection.findOne({ email: value.email });
  if (existing && existing._id.toString() !== req.session.userId) {
    return res
      .status(400)
      .send("That email is already in use by another account.");
  }

  // Build update object
  const updates = {
    firstName: value.firstName,
    lastName: value.lastName,
    email: value.email
  };

  if(req.file){
    const fullBuffer = await sharp(req.file.buffer)
      .resize({ width: 1080, withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toBuffer();
    const thumbBuffer = await sharp(req.file.buffer)
      .resize({ width: 400, withoutEnlargement: true })
      .jpeg({ quality: 70 })
      .toBuffer();
    updates.image = { data: fullBuffer, contentType: "image/jpeg" };
    updates.thumbnail = { data: thumbBuffer, contentType: "image/jpeg" };
    console.log('image updated')
  }

  if (user.role === "seller") {
    updates.address = { 
      address, 
      city, 
      province, 
      postalCode 
    };
  }

  // Only sellers have languages, but they manage those elsewhere (/languages)
  // So we don't touch languages here

  await userCollection.updateOne(
    { _id: new ObjectId(req.session.userId) },
    { $set: updates }
  );

  res.redirect("/profile");
});

// --- OTHER MISC ROUTES ---
app.get("/contacts", async (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }

  const currentUserIdString = req.session.userId;
  const currentUserId = new ObjectId(currentUserIdString);

  try {
    // Find all chat messages where the current user is either the sender or receiver
    // Then, get the distinct other user IDs from those messages.
    const distinctSenderIds = await chatMessageCollection.distinct("senderId", {
      receiverId: currentUserId,
    });
    const distinctReceiverIds = await chatMessageCollection.distinct(
      "receiverId",
      { senderId: currentUserId }
    );

    // Combine and get unique IDs, excluding the current user itself
    const allInteractedUserIds = [
      ...new Set([...distinctSenderIds, ...distinctReceiverIds]),
    ]
      .filter((id) => id.toString() !== currentUserIdString)
      .map((id) => new ObjectId(id)); // Convert back to ObjectId for DB query

    // ...
    let contacts = [];
    if (allInteractedUserIds.length > 0) {
      contacts = await userCollection
        .find(
          { _id: { $in: allInteractedUserIds } },
          {
            projection: {
              /* ... */
            },
          }
        )
        .toArray();
    }

    res.render("contacts", {
      title: "My Messages",
      contacts: contacts, // 'contacts' will be an empty array if no interactions
      currentUserId: currentUserIdString,
    });
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).render("errorPage", {
      title: "Error",
      errorMessage: "Could not load your messages.",
    });
  }
});

// Your existing /chat route should mostly remain the same.
// It's what the links from the contacts page will point to.
app.get("/chat", async (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  const currentUserId = req.session.userId; // String
  const otherUserIdString = req.query.with; // String

  if (
    !otherUserIdString ||
    !ObjectId.isValid(otherUserIdString) ||
    currentUserId === otherUserIdString
  ) {
    return res
      .status(400)
      .render("errorPage", {
        title: "Chat Error",
        errorMessage: "Invalid chat parameters.",
      });
  }
  try {
    // Fetch other user's details for the chat page header
    const otherUser = await userCollection.findOne(
      { _id: new ObjectId(otherUserIdString) },
      { projection: { firstName: 1, lastName: 1 } }
    );
    if (!otherUser) {
      return res
        .status(404)
        .render("errorPage", {
          title: "Chat Error",
          errorMessage: "Chat partner not found.",
        });
    }

    // Construct chatId consistently
    const ids = [currentUserId, otherUserIdString].sort(); // Sort to ensure chatId is always the same for two users
    const chatId = ids.join("-");

    res.render("chat", {
      // This is your existing chat.ejs
      title: `Chat with ${otherUser.firstName || "User"}`,
      currentUserId: currentUserId,
      currentUserFirstName: req.session.firstName, // Assuming this is in session
      otherUserId: otherUserIdString,
      otherUserName: `${otherUser.firstName || ""} ${otherUser.lastName || ""
        }`.trim(),
      chatId: chatId,
    });
  } catch (error) {
    console.error("GET /chat error:", error);
    res
      .status(500)
      .render("errorPage", {
        title: "Server Error",
        errorMessage: "Error loading chat.",
      });
  }
});
app.get("/map", async (req, res) => {
  // General map page, if needed
  if (!req.session.authenticated) return res.redirect("/login");

  const sellers = await userCollection.find({ role: "seller" }).toArray();

  res.render("map", {
    title: "Map",
    mapboxToken: process.env.MAPBOX_API_TOKEN,
    sellers: sellers,
  });
});

// --- SOCKET.IO ---
io.on("connection", (socket) => {
  const session = socket.request.session;
  if (!session || !session.authenticated) {
    socket.disconnect(true);
    return;
  }
  console.log(
    `User ${session.firstName} (${session.userId}) connected with socket ${socket.id}`
  );
  socket.on("joinChat", (chatId) => {
    if (chatId && typeof chatId === "string" && chatId.includes("-")) {
      socket.join(chatId);
      console.log(
        `Socket ${socket.id} (User: ${session.userId}) joined chat room: ${chatId}`
      );
    }
  });
  socket.on("disconnect", () => {
    console.log(
      `User disconnected: ${socket.id} (User: ${session.firstName || "Unknown"
      })`
    );
  });
});

// --- 404 AND ERROR HANDLER ---
app.use((req, res, next) => {
  res.status(404).render("404", { title: "Page Not Found" });
});

app.use((err, req, res, next) => {
  console.error("Global error for URL:", req.originalUrl, "\n", err.stack);
  if (!res.headersSent) {
    res.status(err.status || 500).render("errorPage", {
      title: "Server Error",
      errorMessage: err.message || "An unexpected server error occurred.",
    });
  } else {
    next(err); // Delegate to default Express error handler if headers sent
  }
});

server.listen(port, () => {
  console.log(`Server with Socket.IO is running on port ${port}`);
});
