import express from "express";
import crypto from "crypto";
import { pool } from "./pool.js";
import { authenticate } from "./auth.js";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import pgSession from "connect-pg-simple";
import fs from "fs";
import { promisify } from "util";
const PgSession = pgSession(session);
import multer from "multer";
import { timeStamp } from "console";
import { exec } from "child_process";
import speakeasy from "speakeasy";
import dotenv from "dotenv";    
import { engine } from "express-handlebars"; // Import Handlebars
import Handlebars from "handlebars"; 

dotenv.config();  
const router = express.Router();
const UserCredentialTable = process.env.UserCredentialTable;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const storage = multer.memoryStorage();
const upload = multer({ storage });
const cookieExpireTime = 12 * 60 * 60 * 1000; // 12 hours
// cookieExpireTime: 2 * 24 * 60 * 60 * 1000, 2 day
// cookieExpireTime:  1* 60 * 1000, 1 min

router.use(
  session({
    store: new PgSession({
      pool: pool, // Connection pool
      tableName: "session", // Use another table-name than the default "session" one
    }),
    secret: process.env.session_seceret_key, // Replace with your secret key
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: cookieExpireTime,
    },
  })
);

router.use((req, res, next) => {
  if (req.session && req.session.user) {
    const userAgent = req.headers["user-agent"];
    const userIp =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const formattedIp = userIp === "::1" ? "127.0.0.1" : userIp;

    req.session.otherInfo = {
      ip: formattedIp,
      browser: userAgent,
    };

    next();
  } else {
    next();
  }
});

// Save the username in a cookie, the cookie user name is use
// for displaying user name in profile menu. This cookie is not use anyelse where.
// So it is safe to use.
router.use(async (req, res, next) => {
  if (req.session && req.session.user) {
    res.cookie("username", req.session.user.username, {
      maxAge: cookieExpireTime,
    });
    const query = `SELECT "Role" FROM "${UserCredentialTable}" WHERE "UserName" = $1`;
    const result = await pool.query(query, [req.session.user.username]);
    if (result.rows.length > 0) {
      req.session.user.role = result.rows[0].Role;
    }
    res.cookie("userRole", req.session.user.role, {
      maxAge: cookieExpireTime,
    });
  }
  next();
});

// Middleware to protect routes
async function validateSession(req, res, next) {
  if (!req.session.user) {
    return res.render("templates/Error/NotLoggedIn.handlebars", {
      currentUrl: req.originalUrl,
    });
  }

  try {
    const { id, sessionId } = req.session.user;
    const query = `SELECT "SessionId", "Active" FROM "${UserCredentialTable}" WHERE "id" = $1`;
    const result = await pool.query(query, [id]);

    // Check if user exists and session ID matches
    if (result.rows.length === 0 || result.rows[0].SessionId !== sessionId) {
      console.log(
        `Session invalidated for user \"${req.session.user.username}\"`
      );
      req.session.destroy();
      // ...existing code...
      return res.render("templates/Error/SessionExpire.handlebars", {
        currentUrl: req.originalUrl,
      });
      // ...existing code...
    }

    // Check if the user account is inactive
    if (!result.rows[0].Active) {
      console.log(
        `Account is inactive for user \"${req.session.user.username}\"`
      );
      req.session.destroy();
      res.clearCookie("connect.sid");
      return res.render("templates/Error/AccountInactive.handlebars", {
        currentUrl: req.originalUrl,
      });
    }

    next(); // Proceed if everything is valid
  } catch (err) {
    console.error("Session validation error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}

async function getAllQuizAss() {
  try {
    const query = 'SELECT * FROM "quizass"'; // Ensure the table name matches the exact case
    const result = await pool.query(query);
    return result.rows;
  } catch (err) {
    console.error("Database connection error:", err);
  }
}

async function getAllBooks() {
  try {
    const query = 'SELECT * FROM "unilibbook"'; // Ensure the table name matches the exact case
    const result = await pool.query(query);
    return result.rows;
  } catch (err) {
    console.error("Database connection error:", err);
  }
}

const checkRoleRestriction = (restrictedRole, requiredRole) => {
  return async (req, res, next) => {
    try {
      if (!req.session || !req.session.user || !req.session.user.id) {
        console.log("User not authenticated");
        return res.render("templates/Error/NotLoggedIn.handlebars", {
          currentUrl: req.originalUrl,
        });
      }

      const userId = req.session.user.id;

      const query = `SELECT "Role" FROM "${UserCredentialTable}" WHERE "id" = $1`;
      const result = await pool.query(query, [userId]);

      if (result.rows.length === 0) {
        return res
          .status(401)
          .json({ success: false, message: "User not found" });
      }

      const userRole = result.rows[0].Role;

      if (userRole === restrictedRole) {
        return res.render("templates/Error/AccessDenied.handlebars", {
          currentRole: userRole,
          requiredRole: requiredRole,
        });
      }

      next();
    } catch (err) {
      console.error("Restriction check error:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
    }
  };
};

const checkRolePermission = (requiredRole) => {
  return async (req, res, next) => {
    try {
      if (!req.session || !req.session.user || !req.session.user.id) {
        console.log("User not authenticated");
        console.log(req.session);
        return res.render("templates/Error/NotLoggedIn.handlebars", {
          currentUrl: req.originalUrl,
        });
      }

      if (requiredRole === "Any" || requiredRole === "any") {
        return next();
      }

      const userId = req.session.user.id;

      const query = `SELECT "Role" FROM "${UserCredentialTable}" WHERE "id" = $1`;
      const result = await pool.query(query, [userId]);

      if (result.rows.length === 0) {
        return res
          .status(401)
          .json({ success: false, message: "User not found" });
      }

      const userRole = result.rows[0].Role;
      if (userRole === "SuperAdmin") {
        return next();
      } else if (userRole !== requiredRole) {
        return res.render("templates/Error/AccessDenied.handlebars", {
          currentRole: userRole,
          requiredRole: requiredRole,
        });
      }

      next();
    } catch (err) {
      console.error("Permission check error:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
    }
  };
};

async function checkRestrictionFromTable(req, res, next) {
  try {
    console.log(`Checking restrictions for user ID: ${req.session.user.id}`);
    const query = `SELECT "userRestriction" FROM "${UserCredentialTable}" WHERE "id" = $1`;
    const result = await pool.query(query, [req.session.user.id]);
    if (result.rows.length > 0) {
      req.session.user.userRestriction = result.rows[0].userRestriction;

      const userRestriction = result.rows[0].userRestriction;
      const restrictedRoutes = userRestriction;

      console.log(`User restrictions: ${JSON.stringify(restrictedRoutes)}`);

      if (
        (restrictedRoutes.get && restrictedRoutes.get.includes(req.path)) ||
        (restrictedRoutes.post && restrictedRoutes.post.includes(req.path))
      ) {
        console.log(`Access restricted for path: ${req.path}`);
        if (restrictedRoutes.get && restrictedRoutes.get.includes(req.path)) {
          return res.render("templates/Error/AccessDenied1.handlebars", {
            currentUrl: req.originalUrl,
          });
        } else if (
          restrictedRoutes.post &&
          restrictedRoutes.post.includes(req.path)
        ) {
          return res.status(403).json({
            success: false,
            message: "You don't have permission to perform this action",
          });
        }
      }
    } else {
      console.log("No restrictions found for user.");
      next();
    }
  } catch (err) {
    console.error("Database connection error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}

router.get(
  "/DatBase",
  validateSession,
  checkRolePermission("SuperAdmin"),
  async (req, res) => {}
);

// checkRolePermission check if User Have required Role if yes then give access
// checkRoleRestriction check if User Have restrictedRole Role if yes then restrict access

router.get("/donation/submit/", validateSession, async (req, res) => {
  res.render("notice/donation/formSubmit.handlebars");
});

//Invoke-RestMethod -Uri http://localhost:3030/terminateAllSessions -Method POST
// Terminate all sessions route
router.post(
  "/terminateAllSessions",
  authenticate(process.env.Main_SECRET_TOKEN),
  async (req, res) => {
    try {
       await pool.query(`UPDATE "${UserCredentialTable}" SET "SessionId" = NULL`);

      // Clear the session table
      await pool.query('DELETE FROM "session"');

      // Destroy all sessions on the server
      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
          return res
            .status(500)
            .json({ success: false, message: "Failed to terminate sessions" });
        }
        console.log("All sessions terminated successfully");
        res.status(200).json({
          success: true,
          message: "All sessions terminated successfully",
        });
      });
    } catch (err) {
      console.error("Database query error during session termination:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
    }
  }
);

router.get("/user/profile", validateSession, async (req, res) => {
  try {
    const { id } = req.session.user;
    const query =
      `SELECT "UserName", "FullName", "Role", "HaveMailAccount" FROM "${UserCredentialTable}" WHERE "id" = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = result.rows[0];

    // Pass the user details to the EJS template
    res.render("mainPages/profile.handlebars", { user: JSON.stringify(user) });
  } catch (err) {
    console.error("Database query error:", err);
    res.status(500).send("Internal Server Error");
  }
});

router.get("/home", validateSession, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT "Role", "FullName" FROM "${UserCredentialTable}" WHERE "id" = $1`,
      [req.session.user.id]
    );
    const user = result.rows[0];

    if (user) {
      res.render("mainPages/home.handlebars", {
        user: req.session.user,
        role: user.Role,
        FullName: user.FullName,
      });
    } else {
      res.status(400).json({ success: false, message: "User not found" });
    }
  } catch (err) {
    console.error("Database query error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/post/submitFeedback", validateSession, async (req, res) => {
  const { feedback } = req.body;

  if (!feedback) {
    console.log("Feedback submission attempt with missing feedback");
    return res
      .status(400)
      .json({ success: false, message: "Feedback is required" });
  }

  try {
    const query = `
      INSERT INTO "feedback" ("user", "feedback", "role", "timeStamp", "pageUrl") 
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;

    const values = [
      req.session.user.username,
      feedback,
      req.session.user.role,
      new Date().toISOString(),
      req.headers.referer || 'Unknown' // Gets the referring URL or 'Unknown' if not available
    ];

    const result = await pool.query(query, values);

    console.log(`Feedback submitted successfully by user: ${req.session.user.username}`);
    res.status(200).json({ 
      success: true, 
      message: "Feedback submitted successfully",
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Error inserting feedback to database:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.get("/dashboard/Unilib/", validateSession, async (req, res) => {
  res.render("mainPages/Unilib/quizass.handlebars");
});

router.get(
  "/api/feedback",
  validateSession,
  checkRolePermission("SuperAdmin"),
  async (_, res) => {
    try {
      const query = 'SELECT * FROM "feedback" ORDER BY "timeStamp" DESC';
      const result = await pool.query(query);
      
      return res.render("mainPages/Userfeedback.handlebars", { 
        data: JSON.stringify(result.rows)
      });
    } catch (err) {
      console.error("Error retrieving feedback:", err);
      res.status(500).json({ 
        success: false, 
        message: "Internal Server Error" 
      });
    }
  }
);

router.get(
  "/dashboard/admin",
  validateSession,
  checkRolePermission("SuperAdmin"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT "id","UserName","Active","FullName","Role","HaveMailAccount","userRestriction" FROM "${UserCredentialTable}"`
      );
      let user = result;
      if (user) {
        user = user.rows;
        res.render("mainPages/adminDashboard.handlebars", { userJ: JSON.stringify(user), user });
      } else {
        res.status(400).json({ success: false, message: "User not found" });
      }
    } catch (err) {
      console.error("Database query error:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
    }
  }
);

router.get("/dashboard/AuthApiKey", validateSession, async (req, res) => {
  try {
    const { username } = req.session.user;
    const query =
      'SELECT "key", "timeStamp" FROM "UserAuthApiKey" WHERE "username" = $1';
    const result = await pool.query(query, [username]);

    if (result.rows.length > 0) {
      const userApiAuthenticationApi = result.rows[0].key;
      const timeStamp = result.rows[0].timeStamp;
      res.render("mainPages/generateAuthApi.handlebars", {
        userApiAuthenticationApi,
        timeStamp,
        username: username,
      });
    } else {
      res.render("mainPages/generateAuthApi.handlebars", {
        userApiAuthenticationApi: "No Key Found, Generate New",
        username: username,
      });
    }
  } catch (err) {
    console.error("Database query error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post("/GenerateAuthApiKey", validateSession, async (req, res) => {
  try {
    const { username } = req.session.user;

    // Delete old record of the user if exists
    const deleteQuery = 'DELETE FROM "UserAuthApiKey" WHERE "username" = $1';
    await pool.query(deleteQuery, [username]);

    let md5Hash;
    let keyExists = true;

    // Ensure the generated key is unique
    while (keyExists) {
      md5Hash = crypto.randomBytes(32).toString("hex");
      const checkQuery = 'SELECT 1 FROM "UserAuthApiKey" WHERE "key" = $1';
      const checkResult = await pool.query(checkQuery, [md5Hash]);
      keyExists = checkResult.rows.length > 0;
    }

    // Insert the username, MD5 hash, and timestamp into the UserAuthApiKey table
    const insertQuery =
      'INSERT INTO "UserAuthApiKey" ("username", "key", "timeStamp") VALUES ($1, $2, $3)';
    const formattedDate = new Date().toLocaleString("en-GB", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "numeric",
      minute: "numeric",
      second: "numeric",
      hour12: true,
    });

    await pool.query(insertQuery, [username, md5Hash, formattedDate]);

    console.log(`API key generated for user: ${username}, key: ${md5Hash}`);
    res
      .status(200)
      .json({
        success: true,
        message: "API key generated successfully",
        apiKey: md5Hash,
        date: formattedDate,
      });
  } catch (err) {
    console.error("Error generating API key:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// Endpoint for validating the session
router.get("/validate-session", async (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ message: "Session is invalid" });
  }
  // If session is valid
  res.status(200).json({ message: "Session is valid" });
});

let count = 0;

function _2fa(token) {
  // Use a shared secret for SuperAdmin stored as an environment variable
  const sharedSecret = process.env.SUPERADMIN_2FA_KEY;
  if (!sharedSecret) {
    return res.status(500).json({ error: "Server configuration error." });
  }

  const tokenValidates = speakeasy.totp.verify({
    secret: sharedSecret,
    encoding: "base32",
    token: token,
    window: 1, // Allows a margin for clock drift, optional
  });

  if (!tokenValidates) {
    return res.status(401).json({ error: "Invalid 2FA code" });
  }
}

router.get("/2fa", async (req, res) => {
  res.render("mainPages/adminDashboard.handlebars");
}); 

// Login route
router.post("/login", async (req, res) => {
  const { username, password, token } = req.body;

  if (!username || !password) {
    console.log("Login attempt with missing username or password");
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  try {
    // Query to check if the username exists
    const userQuery = `SELECT * FROM "${UserCredentialTable}" WHERE "UserName" = $1`;
    const userResult = await pool.query(userQuery, [username]);

    if (userResult.rows.length === 0) {
      console.log(`Login attempt with non-existent username: \"${username}\"`);
      return res
        .status(404)
        .json({ success: false, message: "Username does not exist" });
    }

    const user = userResult.rows[0];

    // Check if the password matches
    if (user.Password !== password) {
      console.log(`Incorrect password attempt for username: \"${username}\"`);
      return res
        .status(401)
        .json({ success: false, message: "Incorrect password" });
    }

    // Check if the account is inactive
    if (!user.Active) {
      console.log(
        `Inactive account login attempt for username: \"${username}\"`
      );
      return res
        .status(403)
        .json({ success: false, message: "Account is inactive" });
    }

    // Check if the password matches
    if (
      user.Role === "SuperAdmin" &&
      user.UserName === "ibnekhalid" &&
      !token &&
      process.env._2faEnable === "true"
    ) {
      console.log(`2FA code required for SuperAdmin: \"${username}\"`);
      return res
        .status(401)
        .json({ success: false, message: "Please Enter 2FA code" });
    }

    if (
      user.Role === "SuperAdmin" &&
      user.UserName === "ibnekhalid" &&
      process.env._2faEnable === "true"
    ) {
      // Use a shared secret for SuperAdmin stored as an environment variable
      let sharedSecret;

      if (user.UserName === "ibnekhalid")
        sharedSecret = process.env.SUPERADMIN_2FA_KEY;
      else if (user.UserName === "maaz.waheed")
        sharedSecret = process.env.SUPERADMIN_2FA_KEY;

      if (!sharedSecret) {
        console.error("Server configuration error: Missing SUPERADMIN_2FA_KEY");
        return res.status(500).json({ error: "Server configuration error." });
      }

      const expectedToken = speakeasy.totp({
        secret: sharedSecret,
        encoding: "base32",
      });

      const tokenValidates = speakeasy.totp.verify({
        secret: sharedSecret,
        encoding: "base32",
        token: token,
        window: 1, // Allows a margin for clock drift, optional
      });

      if (!tokenValidates) {
        console.log(
          `Invalid 2FA code for SuperAdmin: \"${username}\". Expected code: ${expectedToken} and received code: ${token}`
        );
        return res
          .status(401)
          .json({ success: false, message: "Invalid 2FA code" });
      }
    }

    // Generate session ID
    const sessionId = crypto.randomBytes(256).toString("hex"); // Generate a secure random session ID
    await pool.query(`UPDATE "${UserCredentialTable}" SET "SessionId" = $1 WHERE "id" = $2`, [
      sessionId,
      user.id,
    ]);

    // Store session ID in session
    req.session.user = {
      id: user.id,
      username: user.UserName,
      sessionId,
    };

    console.log(`User \"${username}\" logged in successfully`);
    res.status(200).json({
      success: true,
      message: "Login successful",
      sessionId,
    });
  } catch (err) {
    console.error("Database query error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// Logout route
router.post("/logout", async (req, res) => {
  if (req.session.user) {
    try {
      const { id, username } = req.session.user;
      const query = `SELECT "Active" FROM "${UserCredentialTable}" WHERE "id" = $1`;
      const result = await pool.query(query, [id]);

      if (result.rows.length > 0 && !result.rows[0].Active) {
        console.log("Account is inactive during logout");
      }

      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
          return res
            .status(500)
            .json({ success: false, message: "Logout failed" });
        }
        res.clearCookie("connect.sid");
        console.log(`User \"${username}\" logged out successfully`);
        res.status(200).json({ success: true, message: "Logout successful" });
      });
    } catch (err) {
      console.error("Database query error during logout:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
    }
  } else {
    res.status(400).json({ success: false, message: "Not logged in" });
  }
});

const rolesAndMembers = [
  {
    role: "Super Admin",
    members: ["Muhammad Bin Khalid", "Maaz Waheed"],
    description: "Top-level access",
  },
  {
    role: "Normal Admin",
    members: ["Not Assign", "Not Assign"],
    description: "Moderater",
  },
];

router.get("/dashboard/Roles&Members", validateSession, async (req, res) => {
  res.render("mainPages/Roles&Members.handlebars", { rolesAndMembers });
}); 

router.get("/dashboard/Unilib/Book", authenticate, async (req, res) => {
  try {
    const result = await getAllBooks();
    res.json(result);
  } catch (err) {
    res.status(500).send("Internal Server Error: " + err);
  }
});

router.get("/dashboard/Unilib/QuizAss", validateSession, async (req, res) => {
  try {
    const result = await getAllQuizAss();
    res.json(result);
  } catch (err) {
    res.status(500).send("Internal Server Error: " + err);
  }
});

router.post("/post/Unilib/QuizAss", validateSession, async (req, res) => {
  const { issueDate, dueDate, subject, description } = req.body;

  if (!issueDate || !dueDate || !subject || !description) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  try {
    // Utility function to align the sequence
    const alignSequence = async () => {
      const maxIdResult = await pool.query(
        "SELECT MAX(id) AS max_id FROM quizass"
      );
      const maxId = maxIdResult.rows[0].max_id || 0; // Default to 0 if the table is empty
      await pool.query(
        "SELECT setval(pg_get_serial_sequence('quizass', 'id'), $1)",
        [maxId]
      );
    };

    // Align the sequence before inserting
    await alignSequence();

    // Insert the new record
    const query =
      'INSERT INTO "quizass" ("issueDate", "dueDate", "subject", "description") VALUES ($1, $2, $3, $4) RETURNING *';
    const values = [issueDate, dueDate, subject, description];
    const result = await pool.query(query, values);

    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Database query error:", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

router.post(
  "/post/donations/submit",
  upload.single("paymentProof"),
  async (req, res) => {
    try {
      // Get form fields
      const { donorName, email, phone, amount } = req.body;

      if (!donorName || !phone || !amount || !req.file) {
        return res
          .status(400)
          .json({ message: "Missing required fields or file." });
      }

      let username = req.session.user.username;
      username = username.replace(/\s+/g, "").toLowerCase();

      const donationBaseFolder = path.join(__dirname, "..", "..", "donation");
      const userFolder = path.join(donationBaseFolder, username);

      if (!fs.existsSync(userFolder)) {
        fs.mkdirSync(userFolder, { recursive: true });
      }

      // Save the uplo
      // aded image file.
      const fileExt = path.extname(req.file.originalname);
      // Name the file "paymentProof" with its original extension.
      const fileName = `paymentProof${fileExt}`;
      const filePath = path.join(userFolder, fileName);
      fs.writeFileSync(filePath, req.file.buffer);

      // Create a JSON file with the submitted data.
      const submissionData = {
        donorName,
        username,
        email: email || null,
        phone,
        amount,
        paymentProof: fileName, // file name saved
        submittedAt: new Date().toISOString(),
      };
      const jsonPath = path.join(userFolder, "data.json");
      fs.writeFileSync(
        jsonPath,
        JSON.stringify(submissionData, null, 2),
        "utf8"
      );

      // Insert data into the donation table.
      const query = `
      INSERT INTO donation (donorname, username, email, phonenumber, amount, paymentproofpath)
      VALUES ($1, $2, $3, $4, $5, $6)
    `;
      const values = [donorName, username, email, phone, amount, filePath];
      await pool.query(query, values);

      res.status(200).json({ message: "Donation submission successful." });
    } catch (error) {
      console.error("Error processing donation submission:", error);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

router.get(
  "/dashboard/addNewUser",
  validateSession,
  checkRolePermission("SuperAdmin"),
  async (req, res) => {
    res.render("mainPages/register.handlebars");
  }
);

router.get(
  "/api/db/table/Users",
  validateSession,
  checkRolePermission("SuperAdmin"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT "id","UserName","Active","FullName","Role","HaveMailAccount","userRestriction" FROM "${UserCredentialTable}"`
      );
      let user = result;
      if (user) {
        user = user.rows;

        res.status(400).json({ user });

        console.log(user.rows);
        /*res.render("mainPages/home.handlebars", {
        user: req.session.user,
        role: user.Role,
        FullName: user.FullName,
      });*/
      } else {
        res.status(400).json({ success: false, message: "User not found" });
      }
    } catch (err) {
      console.error("Database query error:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal Server Error" });
    }
  }
);

router.post(
  "/copy",
  authenticate(process.env.Main_SECRET_TOKEN),
  (req, res) => {
    const neonConnectionString = process.env.NEON_POSTGRES;
    const localConnectionString = process.env.LOCAL_POSTGRES;

    if (!neonConnectionString || !localConnectionString) {
      console.error(
        "Missing Neon or local PostgreSQL connection string in environment."
      );
      return res
        .status(500)
        .json({
          error:
            "Missing Neon or local PostgreSQL connection string in environment.",
        });
    }
    const isLinux = process.env.IsLinux;
    // Using full paths for Windows
    let pgDumpPath;
    let psqlPath;

    if (isLinux === "true") {
      pgDumpPath = "pg_dump";
      psqlPath = "psql";
    } else {
      pgDumpPath = `"C:\\Program Files\\PostgreSQL\\17\\bin\\pg_dump.exe"`;
      psqlPath = `"C:\\Program Files\\PostgreSQL\\17\\bin\\psql.exe"`;
    }

    const command = `${pgDumpPath} "${neonConnectionString}" | ${psqlPath} "${localConnectionString}"`;

    console.log("Executing command:", command);

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error("Error copying DB:", error);
        return res.status(500).json({ error: error.message, stderr });
      }
      console.log("Database copied successfully");
      res.json({ message: "Database copied successfully", output: stdout });
    });
  }
);

export default router;
