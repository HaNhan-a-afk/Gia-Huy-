const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

if (!DATABASE_URL) {
  console.error("❌ Chưa có DATABASE_URL");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(cookieParser());


// ===============================
// TẠO BẢNG DATABASE
// ===============================
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255),
      password_hash TEXT NOT NULL,
      balance BIGINT NOT NULL DEFAULT 0,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      product_id INTEGER,
      product_name TEXT NOT NULL,
      amount BIGINT NOT NULL,
      upgrade_email TEXT,
      delivery_link TEXT,
      status VARCHAR(50) NOT NULL DEFAULT 'Chờ xử lý',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type VARCHAR(30) NOT NULL,
      amount BIGINT NOT NULL,
      note TEXT,
      status VARCHAR(50) NOT NULL DEFAULT 'Chờ xử lý',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("✅ Database đã sẵn sàng");
}


// ===============================
// TRANG KIỂM TRA SERVER
// ===============================
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Gia Huy Shop Backend đang hoạt động"
  });
});


// ===============================
// ĐĂNG KÝ
// ===============================
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Vui lòng nhập tên tài khoản và mật khẩu"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Mật khẩu phải có ít nhất 6 ký tự"
      });
    }

    const check = await pool.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (check.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Tên tài khoản đã tồn tại"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, balance, role`,
      [username, email || null, passwordHash]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: "Đăng ký thành công",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        balance: user.balance,
        role: user.role
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Lỗi server khi đăng ký"
    });
  }
});


// ===============================
// ĐĂNG NHẬP
// ===============================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Sai tài khoản hoặc mật khẩu"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: "Sai tài khoản hoặc mật khẩu"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: "Đăng nhập thành công",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        balance: user.balance,
        role: user.role
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Lỗi server khi đăng nhập"
    });
  }
});


// ===============================
// ĐĂNG XUẤT
// ===============================
app.post("/api/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none"
  });

  res.json({
    success: true,
    message: "Đã đăng xuất"
  });
});


// ===============================
// LẤY THÔNG TIN TÀI KHOẢN
// ===============================
app.get("/api/me", async (req, res) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Chưa đăng nhập"
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      `SELECT id, username, email, balance, role
       FROM users
       WHERE id = $1`,
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Tài khoản không tồn tại"
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Phiên đăng nhập không hợp lệ"
    });
  }
});


// ===============================
// MIDDLEWARE KIỂM TRA ĐĂNG NHẬP
// ===============================
function requireAuth(req, res, next) {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Bạn chưa đăng nhập"
      });
    }

    req.user = jwt.verify(token, JWT_SECRET);

    next();

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Phiên đăng nhập hết hạn"
    });
  }
}


// ===============================
// TẠO ĐƠN HÀNG
// ===============================
app.post("/api/orders", requireAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      productId,
      productName,
      amount,
      upgradeEmail,
      deliveryLink
    } = req.body;

    if (!productId || !productName || !amount) {
      return res.status(400).json({
        success: false,
        message: "Thiếu thông tin sản phẩm"
      });
    }

    await client.query("BEGIN");

    const userResult = await client.query(
      "SELECT balance FROM users WHERE id = $1 FOR UPDATE",
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Không tìm thấy tài khoản"
      });
    }

    const balance = Number(userResult.rows[0].balance);

    if (balance < Number(amount)) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        success: false,
        message: "Số dư không đủ"
      });
    }

    const newBalance = balance - Number(amount);

    await client.query(
      "UPDATE users SET balance = $1 WHERE id = $2",
      [newBalance, req.user.id]
    );

    const orderResult = await client.query(
      `INSERT INTO orders
       (user_id, product_id, product_name, amount, upgrade_email, delivery_link, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'Đã hoàn thành')
       RETURNING *`,
      [
        req.user.id,
        productId,
        productName,
        amount,
        upgradeEmail || null,
        deliveryLink || null
      ]
    );

    await client.query(
      `INSERT INTO transactions
       (user_id, type, amount, note, status)
       VALUES ($1, 'purchase', $2, $3, 'Đã hoàn tất')`,
      [
        req.user.id,
        -Number(amount),
        `Mua ${productName}`
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Mua hàng thành công",
      balance: newBalance,
      order: orderResult.rows[0]
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể tạo đơn hàng"
    });

  } finally {
    client.release();
  }
});
// ===============================
// TẠO YÊU CẦU NẠP TIỀN
// ===============================
app.post("/api/topup", requireAuth, async (req, res) => {
  try {
    const { amount, note } = req.body;

    const money = Number(amount);

    if (!Number.isFinite(money) || money <= 0) {
      return res.status(400).json({
        success: false,
        message: "Số tiền nạp không hợp lệ"
      });
    }

    if (money < 10000) {
      return res.status(400).json({
        success: false,
        message: "Số tiền nạp tối thiểu là 10.000đ"
      });
    }

    const result = await pool.query(
      `INSERT INTO transactions
       (user_id, type, amount, note, status)
       VALUES ($1, 'topup', $2, $3, 'Chờ xử lý')
       RETURNING *`,
      [
        req.user.id,
        money,
        note || "Yêu cầu nạp tiền"
      ]
    );

    res.json({
      success: true,
      message: "Đã tạo yêu cầu nạp tiền",
      transaction: result.rows[0]
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể tạo yêu cầu nạp tiền"
    });
  }
});


// ===============================
// LỊCH SỬ ĐƠN HÀNG
// ===============================
app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM orders
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      success: true,
      orders: result.rows
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể lấy lịch sử đơn hàng"
    });
  }
});


// ===============================
// LỊCH SỬ GIAO DỊCH
// ===============================
app.get("/api/transactions", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM transactions
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      success: true,
      transactions: result.rows
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể lấy lịch sử giao dịch"
    });
  }
});


// ===============================
// KHỞI ĐỘNG SERVER
// ===============================
async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, () => {
      console.log(`🚀 Gia Huy Shop Backend chạy tại port ${PORT}`);
    });

  } catch (error) {
    console.error("❌ Không thể khởi động server:", error);
    process.exit(1);
  }
}

startServer();
