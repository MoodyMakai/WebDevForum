// server.js
const express = require("express");
const exphbs = require("express-handlebars");
const cookieSession = require("cookie-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;


const users = []; 
const comments = []; 

// Middleware 
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "../public")));

app.use(
  cookieSession({
    name: "session",
    keys: ["superinsecurekey"], // intentionally insecure
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  })
);

// ----------- View Engine Setup -----------
app.engine(
  "hbs",
  exphbs.engine({
    extname: ".hbs",
    defaultLayout: "main",
    layoutsDir: path.join(__dirname, "views/layouts"),
    partialsDir: path.join(__dirname, "views/partials"),
  })
);
app.set("view engine", "hbs");
app.set("views", path.join(__dirname, "views"));

// ----------- Debug Logger -----------
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ----------- Helper Middleware -----------
function requireAuth(req, res, next) {
  if (!req.session.username) {
    return res.redirect("/login");
  }
  next();
}

// ----------- Routes -----------

// Home
app.get("/", (req, res) => {
  res.render("index", {
    title: "Insecure Forum",
    username: req.session.username,
  });
});

// Register Page
app.get("/register", (req, res) => {
  res.render("register", { title: "Register" });
});

// Handle Registration
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (users.find((u) => u.username === username)) {
    return res.status(400).send("taken");
  }

  // No hashing, no validation — intentionally insecure
  users.push({ username, password });
  console.log("Registered users:", users);
  res.redirect("/login");
});

// Login Page
app.get("/login", (req, res) => {
  res.render("login", { title: "Login" });
});

// Handle Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).send("wrong");
  }

  req.session.username = username;
  console.log(`User logged in: ${username}`);
  res.redirect("/feed");
});

// Logout
app.get("/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

// Feed Page
app.get("/feed", requireAuth, (req, res) => {
  res.render("feed", {
    title: "Public Feed",
    comments,
    username: req.session.username,
  });
});

// Handle Comment Submission
app.post("/comment", requireAuth, (req, res) => {
  const { comment } = req.body;
  comments.push({ author: req.session.username, text: comment });
  console.log("New comment:", { author: req.session.username, text: comment });
  res.redirect("/feed");
});

// ----------- Start Server -----------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

