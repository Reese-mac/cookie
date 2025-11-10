import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// ✅ 讓 public 資料夾內的檔案可被存取
app.use(express.static(path.join(__dirname, "public")));

// ✅ 首頁導向
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
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
  secure: true, // ✅ 這行一定要加上（HTTPS 必須）
  sameSite: "strict",
  maxAge: 7 * 24 * 60 * 60 * 1000,
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
