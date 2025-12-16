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
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

//Enforce password security
function isStrongPassword(password) {
  const minLength = 8;
  const upper = /[A-Z]/;
  const lower = /[a-z]/;
  const number = /[0-9]/;
  const special = /[^A-Za-z0-9]/;

  return (
    password.length >= minLength &&
    upper.test(password) &&
    lower.test(password) &&
    number.test(password) &&
    special.test(password)
  );
}

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

// Registration with async hashing logic, and min security reqs
app.post("/register", async (req, res) => {
  const { username, password, display_name } = req.body;

  if (!username || !password || !display_name) {
    return res.render("register", {
      error: "All fields are required"
    });
  }

  if (display_name === username) {
    return res.render("register", {
      error: "Display name must be different from username"
    });
  }

  try {
    const hash = await argon2.hash(password);

    db.prepare(`
      INSERT INTO users (
        username,
        password,
        display_name,
        failed_login_attempts,
        lock_until
      )
      VALUES (?, ?, ?, 0, NULL)
    `).run(username, hash, display_name);

    res.redirect("/login");
  } catch (err) {
    console.error(err);

    let message = "Registration failed";

    if (err.message.includes("users.username")) {
      message = "Username already exists";
    } 

    res.render("register", { error: message });
  }
});



// Login 
app.get("/login", (req, res) => {
  res.render("login", { title: "Login" });
});

// Handle Login also with argon support
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // 1Fetch user
  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  // If user doesn't exist 
  if (!user) {
    db.prepare(`
      INSERT INTO login_attempts (username, ip_address, success)
      VALUES (?, ?, 0)
    `).run(username, req.ip);

    return res.render("login", { error: "Invalid username or password" });
  }

  // Check account lock
  if (user.lock_until && new Date(user.lock_until) > new Date()) {
    return res.render("login", {
      error: "Account locked. Try again later."
    });
  }

  // Verify password
  const valid = await argon2.verify(user.password, password);

  //  Password incorrect
  if (!valid) {
    const attempts = user.failed_login_attempts + 1;

    let lockUntil = null;
    if (attempts >= 5) {
      lockUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    }

    // Update user security state
    db.prepare(`
      UPDATE users
      SET failed_login_attempts = ?, lock_until = ?
      WHERE id = ?
    `).run(attempts, lockUntil, user.id);

    // Log failed attempt
    db.prepare(`
      INSERT INTO login_attempts (user_id, username, ip_address, success)
      VALUES (?, ?, ?, 0)
    `).run(user.id, username, req.ip);

    return res.render("login", {
      error: attempts >= 5
        ? "Account locked due to too many failed attempts."
        : "Invalid username or password"
    });
  }

  //Password correct, Reset counters
  db.prepare(`
    UPDATE users
    SET failed_login_attempts = 0,
        lock_until = NULL
    WHERE id = ?
  `).run(user.id);

  // Log successful login
  db.prepare(`
    INSERT INTO login_attempts (user_id, username, ip_address, success)
    VALUES (?, ?, ?, 1)
  `).run(user.id, username, req.ip);

  //  Establish session
  req.session.user = {
    id: user.id,
    username: user.username,
    display_name: user.display_name
  };

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

  const userId = req.session.user.id;

  db.prepare(`
    INSERT INTO comments (user_id, content)
    VALUES (?, ?)
  `).run(userId, comment);

  res.redirect("/feed");
});



app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

