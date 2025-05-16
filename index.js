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

const saltRounds = 12;
const app = express();
const server = http.createServer(app); // Create HTTP server for Socket.IO
const io = new Server(server, {
  cors: {
    origin: "*", // Be more specific in production, e.g., "http://localhost:3000" or your frontend URL
    methods: ["GET", "POST"],
  },
});

const expireTime = 1 * 60 * 60 * 1000; // 1 hour
const port = process.env.PORT || 3000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_db = process.env.MONGODB_DB;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

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

// Express middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json()); // For parsing application/json
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
                postings: postings
                // mapboxToken could be added here if sellerHome.ejs uses a map
                // mapboxToken: process.env.MAPBOX_API_TOKEN
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

            app.get("/cart", (req, res) => {
                if (!req.session.authenticated || req.session.role !== "buyer") {
                    return res.redirect("/login");
                }
                res.render("cart", { title: "Your Cart" });
            });
        } else {
            // Should not happen if role is always set, but as a fallback:
            res.redirect("/login");
        }
    } else {
        res.render("landing", { title: "Landing" });
    }
});

// Signup page
app.get("/signup", (req, res) => {
  res.render("signup", { title: "Sign Up" });
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
  const { firstName, lastName, email, password, role } = req.body;
  const schema = Joi.object({
    firstName: Joi.string().alphanum().min(1).max(50).required(),
    lastName: Joi.string().alphanum().min(1).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(100).required(), // Min 6 char password
    role: Joi.string().valid("buyer", "seller").required(),
  });

  const validationResult = schema.validate(req.body);
  if (validationResult.error) {
    return res.status(400).send(
        validationResult.error.details[0].message +
        ' <a href="/signup">Try again</a>'
    );
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
app.get("/map", (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  res.render("map", {
    title: "Map",
    mapboxToken: process.env.MAPBOX_API_TOKEN,
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