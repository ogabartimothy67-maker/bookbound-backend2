const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());

// 🧠 DATABASE INIT
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) console.error("Database error:", err.message);
  else console.log("✅ Connected to database");
});

// 🧱 CREATE TABLE IF NOT EXISTS
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT
)`);

// ✅ SIGNUP ENDPOINT
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ error: "Missing fields." });

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
    [name, email, hashed],
    (err) => {
      if (err) {
        if (err.message.includes("UNIQUE"))
          return res.status(400).json({ error: "Email already exists." });
        return res.status(500).json({ error: "Database error." });
      }
      res.json({ message: "Account created successfully." });
    }
  );
});

// ✅ LOGIN ENDPOINT  ← 🆕 Added this section
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Missing email or password." });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error." });
    if (!user) return res.status(401).json({ error: "Invalid email or password." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ error: "Invalid email or password." });

    res.json({ message: "Login successful!", user: { id: user.id, name: user.name, email: user.email } });
  });
});


app.get("/users", (req, res) => {
  db.all("SELECT id, name, email FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete("/users/:id", (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM users WHERE id = ?", [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "User deleted successfully." });
  });
});


app.put("/users/:id/reset", async (req, res) => {
  const { id } = req.params;
  const newPassword = "new12345";
  const hashed = await bcrypt.hash(newPassword, 10);

  db.run(
    "UPDATE users SET password = ? WHERE id = ?",
    [hashed, id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: `Password reset. New password: ${newPassword}` });
    }
  );
});

// 🚀 SERVER
const PORT = 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
