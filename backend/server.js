const express = require("express");
const exphbs = require("express-handlebars");
const cookieSession = require("cookie-session");
const path = require("path");
const argon2 = require("argon2");

const app = express();
const PORT = process.env.PORT || 3000;

const db = require("./db/database");


// Middleware 
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "/public")));


app.use(
  cookieSession({
    name: "session",
    keys: ["superinsecurekey"], 
    maxAge: 24 * 60 * 60 * 1000, 
  })
);

//View Engine 
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

// Debug Logger 
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Middleware
function requireAuth(req, res, next) {
  if (!req.session.username) {
    return res.redirect("/login");
  }
  next();
}

// Routes

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

// Registration with async hashing logic
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await argon2.hash(password);

    db.prepare(
      "INSERT INTO users (username, password) VALUES (?, ?)"
    ).run(username, hashedPassword);

    res.redirect("/login");
  } catch (err) {
    res.render("register", { error: "Username already exists" });
  }
});


// Login 
app.get("/login", (req, res) => {
  res.render("login", { title: "Login" });
});

// Handle Login also with argon support
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user) {
    return res.render("login", { error: "Invalid credentials" });
  }

  const valid = await argon2.verify(user.password, password);

  if (!valid) {
    return res.render("login", { error: "Invalid credentials" });
  }

  req.session.username = username;
  res.redirect("/feed");
});



// Logout
app.get("/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

// Feed 
app.get("/feed", requireAuth, (req, res) => {
  const stmt = db.prepare(`
    SELECT comments.content, users.username
    FROM comments
    JOIN users ON comments.user_id = users.id
    ORDER BY comments.created_at DESC
  `);

  const comments = stmt.all();

  res.render("feed", {
    username: req.session.username,
    comments
  });
});


app.get("/user", requireAuth, (req, res) => {
  res.render("user", {
    user: {
    displayName: req.session.username
  },
  customizationOptions: ["Rojo", "Verde", "Blue"]
  });
});

// comment
app.post("/comment", requireAuth, (req, res) => {
  const { comment } = req.body;

  const userStmt = db.prepare(
    "SELECT id FROM users WHERE username = ?"
  );
  const user = userStmt.get(req.session.username);

  const stmt = db.prepare(
    "INSERT INTO comments (user_id, content) VALUES (?, ?)"
  );
  stmt.run(user.id, comment);

  res.redirect("/feed");
});



app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

