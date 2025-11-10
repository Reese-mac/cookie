import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// === 基本設定 ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// === 靜態檔案設定 ===
app.use(express.static(path.join(__dirname, "public")));

// === 首頁 ===
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// === 子頁面 ===
app.get("/cart", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "cart.html"));
});

app.get("/checkout", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "checkout.html"));
});

app.get("/library", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "library.html"));
});

// === 啟動伺服器（本地測試用） ===
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

// === 匯出給 Vercel 使用 ===
export default app;
