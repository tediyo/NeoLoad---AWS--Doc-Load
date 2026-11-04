require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const multer = require("multer");
const crypto = require("crypto");
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const BUCKET = process.env.S3_BUCKET;
const s3 = new S3Client({ region: process.env.AWS_REGION || "eu-north-1" });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });

// ---------- database ----------
const db = new Database(process.env.DB_PATH || "app.db");
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    s3_key TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// ---------- helpers ----------
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const page = (title, body) =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title></head>
   <body style="font-family:sans-serif;max-width:640px;margin:40px auto">${body}</body></html>`;

function auth(kind) {
  return (req, res, next) => {
    try {
      req.user = jwt.verify(req.cookies.token, JWT_SECRET);
      next();
    } catch {
      if (kind === "api") return res.status(401).json({ error: "unauthorized" });
      res.redirect("/login");
    }
  };
}

// ---------- app ----------
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => res.send("ok"));

app.get("/", (req, res) =>
  res.send(page("Home", `<h1>Welcome</h1><p><a href="/documents">Documents</a></p>
    <p><a href="/login">Login</a> | <a href="/register">Register</a></p>`))
);

// ----- register -----
app.get("/register", (req, res) =>
  res.send(page("Register", `<h1>Register</h1>
    <form method="post" action="/register">
      <p><input name="username" placeholder="username" required></p>
      <p><input name="password" type="password" placeholder="password" required></p>
      <button>Register</button>
    </form>`))
);

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6)
    return res.status(400).send(page("Register", "<p>Username and a password of 6+ characters are required.</p>"));
  try {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
    res.redirect("/login");
  } catch {
    res.status(409).send(page("Register", "<p>Username already exists.</p>"));
  }
});

// ----- login -----
app.get("/login", (req, res) =>
  res.send(page("Login", `<h1>Login</h1>
    <form method="post" action="/login">
      <p><input name="username" placeholder="username" required></p>
      <p><input name="password" type="password" placeholder="password" required></p>
      <button>Login</button>
    </form>`))
);

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username || "");
  if (!user || !bcrypt.compareSync(password || "", user.password_hash))
    return res.status(401).send(page("Login", "<p>Invalid username or password.</p>"));
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });
  res.cookie("token", token, { httpOnly: true, sameSite: "lax" });
  res.redirect("/documents");
});

// ----- documents list page -----
app.get("/documents", auth("page"), (req, res) => {
  const docs = db.prepare("SELECT id, filename FROM documents WHERE user_id = ?").all(req.user.id);
  const rows = docs.length
    ? docs.map((d) => `<li><a href="/documents/${d.id}/view">${esc(d.filename)}</a></li>`).join("")
    : "<li>No documents yet.</li>";
  res.send(page("My Documents", `<h1>My Documents</h1>
    <p>Signed in as ${esc(req.user.username)}</p>
    <ul>${rows}</ul>
    <h3>Upload a PDF (max 1 MB)</h3>
    <form method="post" action="/api/documents?redirect=1" enctype="multipart/form-data">
      <input type="file" name="file" accept="application/pdf" required>
      <button>Upload</button>
    </form>`));
});

// ----- documents API -----
app.get("/api/documents", auth("api"), (req, res) => {
  res.json(db.prepare("SELECT id, filename FROM documents WHERE user_id = ?").all(req.user.id));
});

app.post("/api/documents", auth("api"), upload.single("file"), async (req, res) => {
  const f = req.file;
  if (!f || f.mimetype !== "application/pdf")
    return res.status(400).json({ error: "A PDF file is required" });
  const key = `uploads/${req.user.id}/${crypto.randomUUID()}.pdf`;
  try {
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: key, Body: f.buffer, ContentType: "application/pdf" }));
    const info = db
      .prepare("INSERT INTO documents (user_id, filename, s3_key) VALUES (?, ?, ?)")
      .run(req.user.id, f.originalname, key);
    if (req.query.redirect) return res.redirect("/documents");
    res.status(201).json({ id: info.lastInsertRowid, filename: f.originalname });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Upload failed" });
  }
});

app.get("/api/documents/:id/url", auth("api"), async (req, res) => {
  const doc = db.prepare("SELECT * FROM documents WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id);
  if (!doc) return res.status(404).json({ error: "not found" });
  try {
    const url = await getSignedUrl(
      s3,
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: doc.s3_key,
        ResponseContentType: "application/pdf",
        ResponseContentDisposition: "inline",
      }),
      { expiresIn: 300 }
    );
    res.json({ url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not create URL" });
  }
});

// ----- viewer page -----
app.get("/documents/:id/view", auth("page"), (req, res) => {
  const doc = db
    .prepare("SELECT id, filename FROM documents WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user.id);
  if (!doc) return res.status(404).send(page("Not found", "<p>Document not found.</p>"));
  res.send(page(doc.filename, `<h1>${esc(doc.filename)}</h1>
    <p><a href="/documents">Back to documents</a></p>
    <iframe id="viewer" style="width:100%;height:600px;border:1px solid #ccc"></iframe>
    <script>
      fetch("/api/documents/${doc.id}/url")
        .then(r => r.json())
        .then(d => { document.getElementById("viewer").src = d.url; });
    </script>`));
});

app.listen(3000, () => console.log("Listening on http://localhost:3000"));