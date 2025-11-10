import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// 靜態檔案：讓 public 裡的 HTML / CSS / JS 可被存取
app.use(express.static(path.join(__dirname, "public")));

// === 首頁導向 index.html 或 portal.html ===
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
  // 若你想改成 portal.html，這行改成：
  // res.sendFile(path.join(__dirname, "public", "portal.html"));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


// === 初始化 SQLite ===
const db = new sqlite3.Database("users.db");
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  cart TEXT DEFAULT '[]'
)`);

// === JWT 驗證中介層 ===
function verifyToken(req, res, next) {
  const token = req.cookies.token; // 🍪 從 cookie 讀取 token
  if (!token) {
    if (req.path !== "/check-login") {
      console.log("⚠️ 沒有 Token，請先登入");
    }
    return res.status(401).json({ success: false, message: "未登入" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.log("❌ Token 驗證失敗：", err.message);
      return res.status(403).json({ success: false, message: "登入已過期" });
    }
    req.user = user;
    next();
  });
}

// === 首頁 ===
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "portal.html"));
});

// === 登入 ===
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) return res.json({ success: false, message: "資料庫錯誤" });
    if (!row) return res.json({ success: false, message: "帳號不存在" });

    const valid = await bcrypt.compare(password, row.password);
    if (!valid) return res.json({ success: false, message: "密碼錯誤" });

    const token = jwt.sign({ username: row.username }, SECRET_KEY, { expiresIn: "7d" });

    // 🍪 儲存於 cookie，七天有效
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 七天
      sameSite: "strict",
    });

    res.json({ success: true, message: "登入成功 ✦", user: { username: row.username } });
  });
});

// === 登出 ===
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true, message: "已登出 ✦" });
});

// === 註冊 ===
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashed], (err) => {
    if (err) return res.json({ success: false, message: "帳號已存在" });
    res.json({ success: true, message: "註冊成功 ✦" });
  });
});

// === 取得會員資料 ===
app.get("/profile", verifyToken, (req, res) => {
  const { username } = req.user;
  db.get("SELECT username, cart FROM users WHERE username = ?", [username], (err, row) => {
    if (err || !row) return res.json({ success: false, message: "找不到使用者" });
    res.json({ success: true, user: row });
  });
});

// === 檢查登入狀態 ===
app.get("/check-login", verifyToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// === 購物車 ===
app.get("/cart", verifyToken, (req, res) => {
  const { username } = req.user;
  db.get("SELECT cart FROM users WHERE username = ?", [username], (err, row) => {
    if (err || !row) return res.json({ success: false, message: "讀取失敗" });
    const cart = JSON.parse(row.cart || "[]");
    res.json({ success: true, cart });
  });
});

app.post("/cart/add", verifyToken, (req, res) => {
  const { product } = req.body;
  const { username } = req.user;

  db.get("SELECT cart FROM users WHERE username = ?", [username], (err, row) => {
    let cart = [];
    if (row && row.cart) cart = JSON.parse(row.cart);
    cart.push(product);

    db.run("UPDATE users SET cart = ? WHERE username = ?", [JSON.stringify(cart), username], (err2) => {
      if (err2) return res.json({ success: false, message: "加入失敗" });
      res.json({ success: true, message: "已加入購物車 ✦", cart });
    });
  });
});

app.post("/cart/remove", verifyToken, (req, res) => {
  const { product } = req.body;
  const { username } = req.user;

  db.get("SELECT cart FROM users WHERE username = ?", [username], (err, row) => {
    if (err || !row) return res.json({ success: false, message: "資料錯誤" });
    let cart = JSON.parse(row.cart || "[]");
    cart = cart.filter((p) => p !== product);
    db.run("UPDATE users SET cart = ? WHERE username = ?", [JSON.stringify(cart), username]);
    res.json({ success: true, message: "已移除商品", cart });
  });
});

// === 靜態頁面導向 ===
app.get("/portal.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "portal.html"));
});

app.get("/profile.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "portal.html"));
});

// ✅ 匯出 app 給 Vercel 使用
export default app;
