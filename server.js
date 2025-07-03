const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "license_db",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Check if setup is needed
let setupMode = !fs.existsSync("./.setup-complete");

// Initialize database tables
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();

    // Create users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        is_admin BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL DEFAULT NULL,
        status ENUM('active', 'suspended', 'deleted') DEFAULT 'active'
      )
    `);

    // Create licenses table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS licenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        license_key VARCHAR(255) NOT NULL UNIQUE,
        user_id INT,
        hardware_id VARCHAR(255),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NULL DEFAULT NULL,
        last_validated TIMESTAMP NULL DEFAULT NULL,
        validation_count INT DEFAULT 0,
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Create access logs table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS access_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        license_id INT,
        hardware_id VARCHAR(255),
        ip_address VARCHAR(45),
        user_agent VARCHAR(255),
        access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(50),
        FOREIGN KEY (license_id) REFERENCES licenses(id)
      )
    `);

    // Create license types table (for future use)
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS license_types (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE,
        duration_hours INT,
        features TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("Database initialized successfully");
    connection.release();
    return true;
  } catch (error) {
    console.error("Error initializing database:", error);
    console.log("Try running update_db.js to fix database schema issues.");
    return false;
  }
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res.status(401).json({ error: "Access token is required" });

  jwt.verify(
    token,
    process.env.JWT_SECRET || "your_jwt_secret",
    (err, user) => {
      if (err)
        return res.status(403).json({ error: "Invalid or expired token" });
      req.user = user;
      next();
    },
  );
};

// Admin middleware
const isAdmin = async (req, res, next) => {
  try {
    const [rows] = await pool.execute(
      "SELECT is_admin FROM users WHERE id = ?",
      [req.user.id],
    );

    if (rows.length > 0 && rows[0].is_admin) {
      next();
    } else {
      res.status(403).json({ error: "Admin privileges required" });
    }
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
};

// Register a new user
app.post("/api/register", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res
      .status(400)
      .json({ error: "Username, password, and email are required" });
  }

  try {
    // Check if username already exists
    const [existingUsers] = await pool.execute(
      "SELECT * FROM users WHERE username = ? OR email = ?",
      [username, email],
    );

    if (existingUsers.length > 0) {
      return res
        .status(400)
        .json({ error: "Username or email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const [result] = await pool.execute(
      "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
      [username, hashedPassword, email],
    );

    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// User login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  try {
    // Get user from database
    const [users] = await pool.execute(
      "SELECT * FROM users WHERE username = ?",
      [username],
    );

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = users[0];

    // Compare password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || "your_jwt_secret",
      { expiresIn: "1d" },
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Failed to log in" });
  }
});

// Generate a new license key (admin only)
app.post("/api/licenses", authenticateToken, isAdmin, async (req, res) => {
  const { userId, expiresAt, expirationHours, expirationDays, comment } =
    req.body;

  try {
    // Generate a unique and secure license key
    function generateLicenseKey() {
      // Create a more structured license key:
      // 1. 2-char product code (HP for HiPlease)
      // 2. 2-char year (last 2 digits)
      // 3. 1-char license type (T=Trial, B=Basic, P=Pro, E=Enterprise)
      // 4. 4-digit sequential number (we'll use random here)
      // 5. 8-char unique identifier (from UUID)
      // 6. 3-digit checksum (simple algorithm)

      const productCode = "HP";
      const year = new Date().getFullYear().toString().substr(-2);
      const licenseTypes = ["T", "B", "P", "E"];
      const licenseType =
        licenseTypes[Math.floor(Math.random() * licenseTypes.length)];
      const sequentialNum = Math.floor(1000 + Math.random() * 9000).toString();
      const uniqueId = uuidv4().replace(/-/g, "").substring(0, 8).toUpperCase();

      const baseKey = `${productCode}-${year}${licenseType}-${sequentialNum}-${uniqueId}`;

      // Calculate simple checksum (sum of char codes mod 1000)
      const charSum =
        baseKey
          .replace(/-/g, "")
          .split("")
          .reduce((sum, char) => sum + char.charCodeAt(0), 0) % 1000;
      const checksum = charSum.toString().padStart(3, "0");

      return `${baseKey}-${checksum}`;
    }

    const licenseKey = generateLicenseKey();

    let expirationDate = null;
    let expirationInfo = "perpetual";

    // Handle expiration date or time period
    if (expiresAt) {
      expirationDate = expiresAt;
      expirationInfo = `specific date: ${expiresAt}`;
    } else if (expirationHours) {
      // Calculate expiration based on hours from now
      const hours = parseInt(expirationHours);
      if (!isNaN(hours) && hours > 0) {
        const now = new Date();
        const futureDate = new Date(now.getTime() + hours * 60 * 60 * 1000);
        // Format date as MySQL TIMESTAMP: YYYY-MM-DD HH:MM:SS
        const year = futureDate.getFullYear();
        const month = String(futureDate.getMonth() + 1).padStart(2, "0");
        const day = String(futureDate.getDate()).padStart(2, "0");
        const hour = String(futureDate.getHours()).padStart(2, "0");
        const minute = String(futureDate.getMinutes()).padStart(2, "0");
        const second = String(futureDate.getSeconds()).padStart(2, "0");

        expirationDate = `${year}-${month}-${day} ${hour}:${minute}:${second}`;
        expirationInfo = `${hours} hours from now`;
        console.log(
          `Created license expiring in ${hours} hours. Expiration time: ${expirationDate}`,
        );
      }
    } else if (expirationDays) {
      // Calculate expiration based on days from now
      const days = parseInt(expirationDays);
      if (!isNaN(days) && days > 0) {
        const now = new Date();
        const futureDate = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
        // Format date as MySQL TIMESTAMP: YYYY-MM-DD HH:MM:SS
        const year = futureDate.getFullYear();
        const month = String(futureDate.getMonth() + 1).padStart(2, "0");
        const day = String(futureDate.getDate()).padStart(2, "0");
        const hour = String(futureDate.getHours()).padStart(2, "0");
        const minute = String(futureDate.getMinutes()).padStart(2, "0");
        const second = String(futureDate.getSeconds()).padStart(2, "0");

        expirationDate = `${year}-${month}-${day} ${hour}:${minute}:${second}`;
        expirationInfo = `${days} days from now`;
        console.log(
          `Created license expiring in ${days} days. Expiration time: ${expirationDate}`,
        );
      }
    }

    // Get user information if userId provided
    let username = null;
    let email = null;

    if (userId) {
      const [users] = await pool.execute(
        "SELECT username, email FROM users WHERE id = ?",
        [userId],
      );

      if (users.length > 0) {
        username = users[0].username;
        email = users[0].email;
      }
    }

    // Create notes field with creation info
    const notes = JSON.stringify({
      created: new Date().toISOString(),
      createdBy: req.user.username,
      assignedTo: username,
      expirationInfo: expirationInfo,
      comment: comment || null,
    });

    // Check if notes column exists
    try {
      // Insert the license into the database
      const [result] = await pool.execute(
        "INSERT INTO licenses (license_key, user_id, expires_at, notes) VALUES (?, ?, ?, ?)",
        [licenseKey, userId || null, expirationDate, notes],
      );

      // Log license creation
      console.log(
        `License ${licenseKey} created by ${req.user.username}${userId ? " for user " + username : ""} (${expirationInfo})`,
      );

      // Format expiration date for response
      const formattedExpiration = expirationDate
        ? new Date(expirationDate).toISOString()
        : null;

      res.status(201).json({
        message: "License created successfully",
        licenseId: result.insertId,
        licenseKey,
        expiresAt: expirationDate,
        expirationFormatted: formattedExpiration,
        expirationInfo: expirationInfo,
        userId: userId,
        username: username,
        email: email,
      });
    } catch (error) {
      if (error.code === "ER_BAD_FIELD_ERROR") {
        // Try the simpler query without notes column
        console.warn("Notes column not found, trying alternative query...");
        const [result] = await pool.execute(
          "INSERT INTO licenses (license_key, user_id, expires_at) VALUES (?, ?, ?)",
          [licenseKey, userId || null, expirationDate],
        );

        console.log(
          `License ${licenseKey} created (without notes) by ${req.user.username}${userId ? " for user " + username : ""} (${expirationInfo})`,
        );
        console.log("Please run update_db.js to fix your database schema.");

        // Format expiration date for response
        const formattedExpiration = expirationDate
          ? new Date(expirationDate).toISOString()
          : null;

        res.status(201).json({
          message: "License created successfully (database needs update)",
          licenseId: result.insertId,
          licenseKey,
          expiresAt: expirationDate,
          expirationFormatted: formattedExpiration,
          expirationInfo: expirationInfo,
          databaseNeedsUpdate: true,
        });
      } else {
        throw error;
      }
    }
  } catch (error) {
    console.error("License creation error:", error);
    res.status(500).json({
      error: "Failed to create license",
      details: error.message,
      suggestion: "Run update_db.js if this is a database schema issue.",
    });
  }
});

// Validate a license key
app.post("/api/licenses/validate", async (req, res) => {
  const { licenseKey, hardwareId } = req.body;

  if (!licenseKey) {
    return res.status(400).json({ error: "License key is required" });
  }

  try {
    // Get license from database
    const [licenses] = await pool.execute(
      "SELECT l.*, u.username, u.email FROM licenses l LEFT JOIN users u ON l.user_id = u.id WHERE l.license_key = ?",
      [licenseKey],
    );

    if (licenses.length === 0) {
      console.log(
        `License validation failed: Invalid key "${licenseKey.substring(0, 8)}..."`,
      );
      return res.status(404).json({
        error: "Invalid license key - This key does not exist in our database",
      });
    }

    const license = licenses[0];
    console.log(
      `License found for key "${licenseKey}", assigned to ${license.username || "no user"}`,
    );

    // Check if license is active
    if (!license.is_active) {
      console.log(
        `License validation failed: Inactive license "${licenseKey}"`,
      );
      return res.status(403).json({
        error:
          "License is inactive - This license has been revoked by an administrator",
        reason: "revoked",
        licenseId: license.id,
      });
    }

    // Initialize time remaining variables
    let timeRemaining = null;
    let daysRemaining = 0;
    let hoursRemaining = 0;
    let minutesRemaining = 0;
    let expirationDate;
    // Check if license has expired
    if (license.expires_at) {
      console.log(typeof license.expires_at);
      // Create date objects for proper comparison
      let now = new Date();
      now = now.toString();
      now = new Date(now + "Z");
      // MySQL TIMESTAMP comes back as YYYY-MM-DD HH:MM:SS format in local timezone
      // We need to properly parse it
      const expirationDateStr = license.expires_at.toString();
      expirationDate = new Date(expirationDateStr + "Z");

      console.log(
        `Validating license: Current time: ${now.toISOString()}, Expiration: ${expirationDate.toISOString()}, Original expiration string: ${expirationDateStr}`,
      );

      if (now > expirationDate) {
        const expiredDuration = now.getTime() - expirationDate.getTime();
        const expiredHours = Math.floor(expiredDuration / (1000 * 60 * 60));
        const expiredDays = Math.floor(expiredHours / 24);

        console.log(
          `License expired ${expiredDays} days and ${expiredHours % 24} hours ago`,
        );
        return res.status(403).json({
          error: `License expired ${expiredDays > 0 ? expiredDays + " days ago" : expiredHours + " hours ago"} - Please renew your license`,
          reason: "expired",
          expiredAt: expirationDate.toISOString(),
          expiredAgo: {
            days: expiredDays,
            hours: expiredHours % 24,
          },
        });
      }

      // Calculate time remaining for response
      const msRemaining = expirationDate.getTime() - now.getTime();
      hoursRemaining = Math.floor(msRemaining / (1000 * 60 * 60));
      minutesRemaining = Math.floor(
        (msRemaining % (1000 * 60 * 60)) / (1000 * 60),
      );
      daysRemaining = Math.floor(hoursRemaining / 24);

      // Create time remaining object
      timeRemaining = {
        daysRemaining: daysRemaining,
        hoursRemaining: hoursRemaining % 24,
        minutesRemaining: minutesRemaining,
        totalHoursRemaining: hoursRemaining,
      };

      console.log(
        `License valid - Time remaining: ${daysRemaining} days, ${hoursRemaining % 24} hours and ${minutesRemaining} minutes`,
      );

      // If license is about to expire (less than 1 day), include warning
      if (daysRemaining < 1 && hoursRemaining < 24) {
        console.log(`License about to expire soon!`);
      }
    }

    // Check hardware binding if applicable
    if (license.hardware_id && license.hardware_id !== hardwareId) {
      console.log(
        `License validation failed: Hardware mismatch. Expected: ${license.hardware_id}, Got: ${hardwareId}`,
      );
      return res.status(403).json({
        error:
          "License is bound to different hardware - This license can only be used on the originally activated device",
        reason: "hardware_mismatch",
        boundTo: license.hardware_id.substring(0, 10) + "...",
        licenseId: license.id,
      });
    }

    // If no hardware binding exists and hardware ID is provided, bind the license
    if (hardwareId && !license.hardware_id) {
      console.log(
        `Binding license ${licenseKey} to hardware ID ${hardwareId.substring(0, 10)}...`,
      );
      await pool.execute("UPDATE licenses SET hardware_id = ? WHERE id = ?", [
        hardwareId,
        license.id,
      ]);
    }

    // Log this access
    const ipAddress = req.ip || req.connection.remoteAddress;
    await pool.execute(
      "INSERT INTO access_logs (license_id, hardware_id, ip_address) VALUES (?, ?, ?)",
      [license.id, hardwareId || null, ipAddress],
    );

    // Time remaining was calculated earlier

    res.json({
      valid: true,
      message: license.expires_at
        ? `License is valid and expires in ${daysRemaining > 0 ? daysRemaining + " days" : hoursRemaining + " hours"}`
        : "License is valid (perpetual)",
      licenseId: license.id,
      username: license.username || null,
      expiresAt: expirationDate,
      expiresAtFormatted: license.expires_at
        ? new Date(license.expires_at).toISOString()
        : null,
      timeRemaining: timeRemaining,
      isPerpetual: !license.expires_at,
      hardwareBound: !!license.hardware_id,
      activatedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("License validation error:", error);
    res.status(500).json({
      error: "Failed to validate license - Server error occurred",
      technicalDetails:
        process.env.NODE_ENV === "development" ? error.message : null,
    });
  }
});

// Get all licenses (admin only)
app.get("/api/licenses", authenticateToken, isAdmin, async (req, res) => {
  try {
    const [licenses] = await pool.execute(`
      SELECT l.*, u.username, u.email
      FROM licenses l
      LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC
    `);

    res.json(licenses);
  } catch (error) {
    console.error("Error fetching licenses:", error);
    res.status(500).json({ error: "Failed to fetch licenses" });
  }
});

// Get individual license details (admin only)
app.get("/api/licenses/:id", authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const [licenses] = await pool.execute(
      `
      SELECT l.*, u.username, u.email
      FROM licenses l
      LEFT JOIN users u ON l.user_id = u.id
      WHERE l.id = ?
    `,
      [id],
    );

    if (licenses.length === 0) {
      return res.status(404).json({ error: "License not found" });
    }

    res.json(licenses[0]);
  } catch (error) {
    console.error("Error fetching license:", error);
    res.status(500).json({ error: "Failed to fetch license" });
  }
});

// Get user's licenses
app.get("/api/users/licenses", authenticateToken, async (req, res) => {
  try {
    const [licenses] = await pool.execute(
      "SELECT * FROM licenses WHERE user_id = ?",
      [req.user.id],
    );

    res.json(licenses);
  } catch (error) {
    console.error("Error fetching user licenses:", error);
    res.status(500).json({ error: "Failed to fetch licenses" });
  }
});

// Revoke a license (admin only)
app.put(
  "/api/licenses/:id/revoke",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    const { id } = req.params;

    try {
      const [result] = await pool.execute(
        "UPDATE licenses SET is_active = NOT is_active WHERE id = ?",
        [id],
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "License not found" });
      }

      res.json({ message: "License revoked successfully" });
    } catch (error) {
      console.error("License revocation error:", error);
      res.status(500).json({ error: "Failed to revoke license" });
    }
  },
);

// Create public directory if it doesn't exist
if (!fs.existsSync("./public")) {
  fs.mkdirSync("./public");
}

// Copy admin panel and setup page to public directory
if (fs.existsSync("admin_panel.html")) {
  fs.copyFileSync("admin_panel.html", "./public/index.html");
}
if (fs.existsSync("public/setup.html")) {
  fs.copyFileSync("public/setup.html", "./public/setup.html");
}

// Serve admin panel or setup wizard at root
app.get("/", (req, res) => {
  if (setupMode) {
    res.sendFile(path.join(__dirname, "public/setup.html"));
  } else {
    res.sendFile(path.join(__dirname, "public/index.html"));
  }
});

// Add API status endpoint
app.get("/api/status", (req, res) => {
  res.json({
    status: "online",
    version: "1.0.0",
    serverTime: new Date().toISOString(),
    setupMode: setupMode,
  });
});

// Setup endpoints
app.post("/api/setup/database", async (req, res) => {
  try {
    const { host, user, password, database } = req.body;

    // Test the connection
    const testConnection = await mysql.createConnection({
      host,
      user,
      password,
    });

    // Create database if it doesn't exist
    await testConnection.query(`CREATE DATABASE IF NOT EXISTS ${database}`);
    await testConnection.end();

    // Update .env file
    const envContent = `PORT=${process.env.PORT || 3000}
DB_HOST=${host}
DB_USER=${user}
DB_PASSWORD=${password}
DB_NAME=${database}
JWT_SECRET=${process.env.JWT_SECRET || uuidv4()}
`;
    fs.writeFileSync(".env", envContent);

    // Reload configuration
    process.env.DB_HOST = host;
    process.env.DB_USER = user;
    process.env.DB_PASSWORD = password;
    process.env.DB_NAME = database;

    // Reconnect to the database
    await pool.end();
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    // Initialize database tables
    await initializeDatabase();

    res.json({ success: true });
  } catch (error) {
    console.error("Database setup error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/setup/admin", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if users table exists and has any users
    const [tables] = await pool.execute(`SHOW TABLES LIKE 'users'`);

    if (tables.length === 0) {
      // Ensure tables exist
      await initializeDatabase();
    }

    // Check if any users exist
    const [users] = await pool.execute("SELECT * FROM users LIMIT 1");

    if (users.length > 0) {
      // Update the first user as admin
      await pool.execute(
        "UPDATE users SET username = ?, password = ?, email = ?, is_admin = true WHERE id = ?",
        [username, hashedPassword, email, users[0].id],
      );
    } else {
      // Create admin user
      await pool.execute(
        "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, true)",
        [username, hashedPassword, email],
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Admin setup error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/setup/config", async (req, res) => {
  try {
    const { port, jwtSecret, enableCors } = req.body;

    // Update .env file with new values, preserving database settings
    // Update .env file
    const envContent = `PORT=${port}
  DB_HOST=${process.env.DB_HOST}
  DB_USER=${process.env.DB_USER}
  DB_PASSWORD=${process.env.DB_PASSWORD}
  DB_NAME=${process.env.DB_NAME}
  JWT_SECRET=${jwtSecret}
  ENABLE_CORS=${enableCors ? "true" : "false"}
  LICENSE_GRACE_PERIOD_HOURS=24
  NODE_ENV=${process.env.NODE_ENV || "production"}
  `;
    fs.writeFileSync(".env", envContent);

    // Update process.env
    process.env.PORT = port;
    process.env.JWT_SECRET = jwtSecret;
    process.env.ENABLE_CORS = enableCors ? "true" : "false";

    // Mark setup as complete
    fs.writeFileSync(
      "./.setup-complete",
      "Setup completed on " + new Date().toISOString(),
    );
    setupMode = false;

    res.json({ success: true });
  } catch (error) {
    console.error("Config setup error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get current user info
app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(
      "SELECT id, username, email, is_admin, created_at FROM users WHERE id = ?",
      [req.user.id],
    );

    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(users[0]);
  } catch (error) {
    console.error("Error fetching user info:", error);
    res.status(500).json({ error: "Failed to fetch user info" });
  }
});

// Get all users (admin only)
app.get("/api/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.execute(
      "SELECT id, username, email, is_admin, created_at FROM users",
    );

    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// Get access logs (admin only)
app.get("/api/logs", authenticateToken, isAdmin, async (req, res) => {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit) : 100;

    const [logs] = await pool.execute(
      `
      SELECT al.*, l.license_key
      FROM access_logs al
      JOIN licenses l ON al.license_id = l.id
      ORDER BY al.access_time DESC
      LIMIT ?
    `,
      [limit],
    );

    res.json(logs);
  } catch (error) {
    console.error("Error fetching logs:", error);
    res.status(500).json({ error: "Failed to fetch logs" });
  }
});

// Add is_admin column if it doesn't exist
async function ensureAdminColumn() {
  try {
    const connection = await pool.getConnection();

    // Check if is_admin column exists
    const [columns] = await connection.execute(`
      SHOW COLUMNS FROM users LIKE 'is_admin'
    `);

    // If column doesn't exist, add it
    if (columns.length === 0) {
      console.log("Adding is_admin column to users table");
      await connection.execute(`
        ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT false
      `);
    }

    connection.release();
  } catch (error) {
    console.error("Error ensuring admin column exists:", error);
  }
}

// Initialize database and start server
const startServer = async () => {
  try {
    let dbInitSuccess = true;

    if (!setupMode) {
      dbInitSuccess = await initializeDatabase();

      if (!dbInitSuccess) {
        console.warn(
          "\x1b[33m%s\x1b[0m",
          "⚠️ Database schema may be incomplete.",
        );
        console.warn(
          "\x1b[33m%s\x1b[0m",
          "⚠️ Run node update_db.js to fix database issues.",
        );
        console.warn(
          "\x1b[33m%s\x1b[0m",
          "⚠️ Or run repair_db.bat for a guided repair process.",
        );
      } else {
        await ensureAdminColumn();
      }
    }

    app.listen(PORT, () => {
      console.log(
        `\x1b[32m%s\x1b[0m`,
        `✅ License server running on port ${PORT}`,
      );
      if (setupMode) {
        console.log(
          `\x1b[36m%s\x1b[0m`,
          `🛠️ Setup wizard available at http://localhost:${PORT}`,
        );
      } else {
        console.log(
          `\x1b[36m%s\x1b[0m`,
          `🚀 Admin panel available at http://localhost:${PORT}`,
        );
        if (!dbInitSuccess) {
          console.log(
            `\x1b[33m%s\x1b[0m`,
            `⚠️ Some features may not work due to database issues.`,
          );
        }
      }
    });
  } catch (err) {
    console.error("\x1b[31m%s\x1b[0m", "❌ Failed to initialize server:", err);
    console.error(
      "\x1b[31m%s\x1b[0m",
      "❌ Check your database connection and try again.",
    );
  }
};

startServer();
