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

const saltRounds = 12;
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Be more specific in production
    methods: ["GET", "POST"],
  },
});

const expireTime = 1 * 60 * 60 * 1000;
const port = process.env.PORT || 3000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_db = process.env.MONGODB_DB;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

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

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + "/public"));
app.set("view engine", "ejs");

// Middleware to make session available to all templates
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// --- Your Original Routes (Kept as close to original as possible) ---
app.get("/", async (req, res) => {
  if (req.session.authenticated) {
    if (req.session.role === "seller") {
      const docs = await postingCollection
        .find({ sellerId: new ObjectId(req.session.userId) })
        .sort({ createdAt: -1 })
        .toArray();
      const postings = docs.map((doc) => ({
        ...doc,
        _id: doc._id.toString(),
        sellerId: doc.sellerId.toString(),
        imageSrc: `data:${
          doc.image.contentType
        };base64,${doc.image.data.toString("base64")}`,
        thumbSrc: `data:${
          doc.thumbnail.contentType
        };base64,${doc.thumbnail.data.toString("base64")}`,
      }));
      res.render("sellerHome", { title: "My Postings", postings: postings });
    } else if (req.session.role === "buyer") {
      const docs = await postingCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
      const postings = docs.map((doc) => ({
        ...doc,
        _id: doc._id.toString(),
        sellerId: doc.sellerId.toString(),
        imageSrc: `data:${
          doc.image.contentType
        };base64,${doc.image.data.toString("base64")}`,
        thumbSrc: `data:${
          doc.thumbnail.contentType
        };base64,${doc.thumbnail.data.toString("base64")}`,
      }));
      res.render("buyerHome", {
        title: "Buyer Home Page",
        mapboxToken: process.env.MAPBOX_API_TOKEN,
        postings: postings,
      });
    } else {
      res.render("landing", { title: "Landing" });
    }
  } else {
    res.render("landing", { title: "Landing" });
  }
});

app.get("/signup", (req, res) => {
  res.render("signup", { title: "Sign Up" });
});

app.get("/login", (req, res) => {
  const error = req.session.error;
  delete req.session.error;
  res.render("login", { title: "Log in", error: error });
});

app.post("/loginSubmit", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });
  const validationResult = schema.validate(
    { email, password },
    { abortEarly: false }
  );
  if (validationResult.error != null) {
    const fields = validationResult.error.details.map((d) => d.context.key);
    const unique = Array.from(new Set(fields));
    const msgs = unique.map((f) => `${f} is required.`).join(" ");
    return res.send(`<p>${msgs}</p><a href="/login">Try again</a>`); // Kept original response
  }
  const result = await userCollection.findOne({ email: email });
  if (!result) {
    req.session.error = "Invalid email/password combination.";
    console.log("email not associated with any account");
    return res.redirect("/login");
  }
  if (await bcrypt.compare(password, result.password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.email = email;
    req.session.firstName = result.firstName;
    req.session.lastName = result.lastName;
    req.session.role = result.role;
    req.session.userId = result._id.toString();
    return res.redirect("/");
  } else {
    console.log("incorrect password");
    // Kept original HTML response for incorrect password
    return res.send(`
      <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Login Error</title></head>
      <body><div class="container"><span>Incorrect password</span><br><a href="/login">Try again</a></div></body></html>
    `);
  }
});

app.post("/signupSubmit", async (req, res) => {
  const { firstName, lastName, email, password, role } = req.body;
  const schema = Joi.object({
    firstName: Joi.string().min(1).required(),
    lastName: Joi.string().min(1).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    role: Joi.string().valid("buyer", "seller").required(),
  });
  const validationResult = schema.validate({
    firstName,
    lastName,
    email,
    password,
    role,
  });
  if (validationResult.error) {
    return res
      .status(400)
      .send(
        validationResult.error.details[0].message +
          ' <a href="/signup">Try again</a>'
      ); // Added link
  }
  const emailExists = await userCollection.findOne({ email });
  if (emailExists) {
    return res
      .status(400)
      .send(
        'Email already registered. <a href="/login">Login</a> or <a href="/signup">try another</a>.'
      ); // Added links
  }
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const { insertedId } = await userCollection.insertOne({
    firstName,
    lastName,
    email,
    password: hashedPassword,
    role,
    languages: role === "seller" ? [] : undefined,
    createdAt: new Date(),
  });
  req.session.authenticated = true;
  req.session.firstName = firstName;
  req.session.lastName = lastName;
  req.session.email = email;
  req.session.role = role;
  req.session.userId = insertedId.toString();
  if (req.session.role === "seller") {
    return res.redirect("/languages");
  }
  return res.redirect("/");
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
  if (!Array.isArray(languages)) languages = [languages];
  await userCollection.updateOne(
    { _id: new ObjectId(req.session.userId) },
    { $set: { languages: languages } }
  );
  console.log("languages written into DB");
  return res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
      return res.status(500).send("Could not log out.");
    }
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
    return res.status(403).redirect("/login"); // Redirect as per original
  }
  if (!req.file) {
    return res
      .status(400)
      .send("No image uploaded. <a href='/createPost'>Try again</a>");
  }
  const { produce, quantity, price, description } = req.body;
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
    return res.redirect("/");
  } catch (error) {
    console.error("Error creating post:", error);
    return res
      .status(500)
      .send("Error processing your post. <a href='/createPost'>Try again</a>");
  }
});

// --- CHAT ROUTES with Enhanced Logging & Error Handling ---
app.get("/chat", async (req, res) => {
  console.log(
    "GET /chat route hit. Query:",
    req.query,
    "Session UserID:",
    req.session.userId
  );
  if (!req.session.authenticated) {
    console.log("GET /chat - Unauthenticated, redirecting to login.");
    return res.redirect("/login");
  }
  const currentUserId = req.session.userId;
  const otherUserIdString = req.query.with;

  let errorMessage = "";
  if (!otherUserIdString)
    errorMessage =
      "No user specified to chat with. Append ?with=USER_ID to the URL.";
  else if (!ObjectId.isValid(otherUserIdString))
    errorMessage = "The user ID for your chat partner is invalid.";
  else if (currentUserId === otherUserIdString)
    errorMessage = "You cannot start a chat with yourself.";

  if (errorMessage) {
    console.log("GET /chat - Error condition:", errorMessage);
    return res
      .status(400)
      .render("errorPage", { title: "Chat Error", errorMessage });
  }

  try {
    const otherUser = await userCollection.findOne(
      { _id: new ObjectId(otherUserIdString) },
      { projection: { firstName: 1, lastName: 1 } }
    );
    if (!otherUser) {
      console.log("GET /chat - Other user not found:", otherUserIdString);
      return res
        .status(404)
        .render("errorPage", {
          title: "Chat Error",
          errorMessage:
            "The user you are trying to chat with could not be found.",
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
      otherUserName: `${otherUser.firstName} ${
        otherUser.lastName || ""
      }`.trim(),
      chatId,
    });
  } catch (error) {
    console.error(
      "GET /chat - CRITICAL ERROR setting up chat page:",
      error.stack
    );
    return res
      .status(500)
      .render("errorPage", {
        title: "Server Error",
        errorMessage:
          "An internal error occurred while trying to load the chat page.",
      });
  }
});

app.get("/api/chat/:chatId/messages", async (req, res) => {
  console.log(
    "GET /api/chat/:chatId/messages - Received for chatId:",
    req.params.chatId,
    "Session UserID:",
    req.session.userId
  );
  if (!req.session.authenticated)
    return res.status(401).json({ error: "Unauthorized" });
  try {
    const { chatId } = req.params;
    const currentUserId = req.session.userId;
    const [user1, user2] = chatId.split("-");
    if (user1 !== currentUserId && user2 !== currentUserId) {
      return res
        .status(403)
        .json({ error: "Forbidden: Not part of this chat." });
    }
    const messagesFromDb = await chatMessageCollection
      .find({ chatId })
      .sort({ timestamp: 1 })
      .toArray();
    const messages = messagesFromDb.map((msg) => ({
      _id: msg._id.toString(),
      chatId: msg.chatId,
      senderId: msg.senderId.toString(),
      receiverId: msg.receiverId.toString(),
      messageType: msg.messageType,
      timestamp: msg.timestamp,
      messageText: msg.messageText || "",
      ...(msg.messageType === "image" &&
        msg.image?.data && {
          imageDataUri: `data:${
            msg.image.contentType
          };base64,${msg.image.data.toString("base64")}`,
        }),
    }));
    console.log(
      "GET /api/chat/:chatId/messages - Sending",
      messages.length,
      "messages."
    );
    return res.json(messages);
  } catch (error) {
    console.error(
      "GET /api/chat/:chatId/messages - CRITICAL ERROR:",
      error.stack
    );
    if (!res.headersSent)
      return res
        .status(500)
        .json({
          error: "Server error fetching messages.",
          details: error.message,
        });
  }
});

app.post("/api/chat/messages", async (req, res) => {
  console.log("-----\nPOST /api/chat/messages RECEIVED");
  console.log("Session UserID:", req.session.userId);
  console.log("Request Body:", req.body);

  if (!req.session.authenticated) {
    console.log("API /api/chat/messages - Error: Unauthorized access attempt.");
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const { chatId, senderId, receiverId, messageText } = req.body;
    let errors = [];
    if (!chatId || typeof chatId !== "string" || !chatId.includes("-"))
      errors.push("Invalid or missing chatId.");
    if (!senderId || senderId !== req.session.userId)
      errors.push("Invalid or mismatched senderId.");
    if (!receiverId || typeof receiverId !== "string")
      errors.push("Invalid or missing receiverId.");
    if (
      !messageText ||
      typeof messageText !== "string" ||
      messageText.trim() === ""
    )
      errors.push("Message text is empty or invalid.");
    if (senderId && !ObjectId.isValid(senderId))
      errors.push("SenderId is not a valid ObjectId format.");
    if (receiverId && !ObjectId.isValid(receiverId))
      errors.push("ReceiverId is not a valid ObjectId format.");
    if (errors.length > 0) {
      console.log(
        "API /api/chat/messages - Validation Errors:",
        errors.join(" ")
      );
      return res
        .status(400)
        .json({ error: "Invalid message data.", details: errors.join(" ") });
    }
    const [user1, user2] = chatId.split("-");
    if (user1 !== req.session.userId && user2 !== req.session.userId) {
      console.log(
        "API /api/chat/messages - Error: User not part of this chat."
      );
      return res
        .status(403)
        .json({ error: "Forbidden: Not part of this chat." });
    }
    console.log(
      "API /api/chat/messages - Validation passed. Preparing document."
    );
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
    console.log(
      "API /api/chat/messages - Message saved. Emitting via Socket.IO to room:",
      chatId
    );
    io.to(chatId).emit("newMessage", savedMessage);
    console.log("API /api/chat/messages - Emitted. Sending 201 JSON response.");
    return res.status(201).json(savedMessage);
  } catch (error) {
    console.error("CRITICAL ERROR in POST /api/chat/messages:", error.stack);
    if (!res.headersSent)
      return res
        .status(500)
        .json({
          error: "Server error while sending message.",
          details: error.message,
        });
    console.error("API /api/chat/messages - Headers already sent.");
  }
});

app.post(
  "/api/chat/messages/image",
  upload.single("chatImage"),
  async (req, res) => {
    console.log("-----\nPOST /api/chat/messages/image RECEIVED");
    console.log("Session UserID:", req.session.userId);
    console.log("Request Body (for image caption etc.):", req.body);
    console.log(
      "Uploaded File info:",
      req.file
        ? {
            originalname: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size,
          }
        : "No file uploaded"
    );

    if (!req.session.authenticated) {
      console.log(
        "API /api/chat/messages/image - Error: Unauthorized access attempt."
      );
      return res.status(401).json({ error: "Unauthorized" });
    }
    try {
      const { chatId, senderId, receiverId, caption } = req.body;
      let errors = [];
      if (!req.file) errors.push("No image file was uploaded.");
      if (!chatId || typeof chatId !== "string" || !chatId.includes("-"))
        errors.push("Invalid or missing chatId.");
      if (!senderId || senderId !== req.session.userId)
        errors.push("Invalid or mismatched senderId.");
      if (!receiverId || typeof receiverId !== "string")
        errors.push("Invalid or missing receiverId.");
      if (senderId && !ObjectId.isValid(senderId))
        errors.push("SenderId is not a valid ObjectId format.");
      if (receiverId && !ObjectId.isValid(receiverId))
        errors.push("ReceiverId is not a valid ObjectId format.");
      if (errors.length > 0) {
        console.log(
          "API /api/chat/messages/image - Validation Errors:",
          errors.join(" ")
        );
        return res
          .status(400)
          .json({
            error: "Invalid image message data.",
            details: errors.join(" "),
          });
      }
      const [user1, user2] = chatId.split("-");
      if (user1 !== req.session.userId && user2 !== req.session.userId) {
        console.log(
          "API /api/chat/messages/image - Error: User not part of this chat."
        );
        return res
          .status(403)
          .json({ error: "Forbidden: Not part of this chat." });
      }
      console.log(
        "API /api/chat/messages/image - Validation passed. Processing image."
      );
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
        senderId: newMessageDocument.senderId.toString(),
        receiverId: newMessageDocument.receiverId.toString(),
        messageType: "image",
        timestamp: newMessageDocument.timestamp,
        messageText: newMessageDocument.messageText,
        imageDataUri: `data:image/jpeg;base64,${imageBuffer.toString(
          "base64"
        )}`,
      };
      console.log(
        "API /api/chat/messages/image - Image message saved. Emitting via Socket.IO to room:",
        chatId
      );
      io.to(chatId).emit("newMessage", savedMessage);
      console.log(
        "API /api/chat/messages/image - Emitted. Sending 201 JSON response."
      );
      return res.status(201).json(savedMessage);
    } catch (error) {
      console.error(
        "CRITICAL ERROR in POST /api/chat/messages/image:",
        error.stack
      );
      if (!res.headersSent)
        return res
          .status(500)
          .json({
            error: "Server error while sending image message.",
            details: error.message,
          });
      console.error("API /api/chat/messages/image - Headers already sent.");
    }
  }
);

// --- Other Routes ---
app.get("/viewpage", (req, res) => {
  /* Your original viewpage */
});
app.get("/contact", (req, res) => {
  /* Your original contact */
});

app.get("/map", (req, res) => {
  if (!req.session.authenticated) return res.redirect("/login");
  res.render("map", {
    title: "Map",
    mapboxToken: process.env.MAPBOX_API_TOKEN,
  });
});

// --- Socket.IO Connection Logic ---
io.on("connection", (socket) => {
  console.log("A user connected via WebSocket:", socket.id);
  const session = socket.request.session;
  if (!session || !session.authenticated) {
    console.log(
      "Socket connection from unauthenticated user. Disconnecting.",
      socket.id
    );
    socket.disconnect(true);
    return;
  }
  console.log(
    `User ${session.firstName} (${session.userId}) connected with socket ${socket.id}`
  );
  socket.on("joinChat", (chatId) => {
    if (chatId && typeof chatId === "string" && chatId.includes("-")) {
      // Basic validation for chatId
      console.log(
        `Socket ${socket.id} (User: ${session.userId}) joining chat room: ${chatId}`
      );
      socket.join(chatId);
    } else {
      console.log(
        `Socket ${socket.id} (User: ${session.userId}) tried to join an invalid chat room: '${chatId}'`
      );
    }
  });
  socket.on("disconnect", () => {
    console.log(
      "User disconnected:",
      socket.id,
      `(User: ${session.firstName || "Unknown"})`
    );
  });
});

// --- 404 and Global Error Handler ---
app.use((req, res) => {
  console.log("404 Not Found:", req.originalUrl);
  res.status(404).render("404", { title: "Page Not Found" });
});

app.use((err, req, res, next) => {
  console.error(
    "Global error handler caught an error for URL:",
    req.originalUrl
  );
  console.error(err.stack);
  // Check if headers already sent. If rendering HTML, it's probably safe.
  // If it was an API call that failed to send JSON, this might still render HTML.
  if (!res.headersSent) {
    return res.status(500).render("errorPage", {
      title: "Server Error",
      errorMessage:
        "An unexpected server error occurred. Please try again later.",
    });
  }
  // If headers sent, we can't do much except log and let Express handle the termination.
  console.log(
    "Headers were already sent for this error. Letting Express handle final termination."
  );
  next(err); // Important if you want Express default error handling to also run
});

server.listen(port, () => {
  console.log(`Server with Socket.IO is running on port ${port}`);
});
