import express from "express";
import path from "path";
import { fileURLToPath } from "url"; 
import dotenv from "dotenv"; // Updated to use import
import mainRoutes from "./routes/main.js";
import { pool } from "./routes/pool.js"; // Import the pool
import nunjucks from "nunjucks";

dotenv.config(); // Use dotenv to load environment variables
const app = express();
app.use(express.json()); // To parse JSON request bodies

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configure Nunjucks
nunjucks.configure("views", {
  autoescape: true, // Automatically escape HTML to prevent XSS
  express: app,     // Connect Nunjucks with Express
  watch: true,      // Watch for file changes (useful in development)
});

app.use("/", mainRoutes);

// Serve static files
app.use(
  "/Assets",
  express.static(path.join(__dirname, "public/Assets"), {
    setHeaders: (res, path) => {
      if (path.endsWith(".css")) {
        res.setHeader("Content-Type", "text/css");
      }
    },
  })
);

// return res.render("");
// render load page from views folder

app.get("/", (req, res) => {
  return res.render("staticPage/index.njk"); // Ensure the file extension is .njk
 });

app.get("/login", (req, res) => {
  if (req.session && req.session.user) {
    return res.render("staticPage/login.njk", { userLoggedIn: true });
  }
  return res.render("staticPage/login.njk");
});

app.get("/Terms&Conditions", (req, res) => {
  if (req.session && req.session.user) {
    return res.render("staticPage/Terms&Conditions.njk", { userLoggedIn: true });
  }
  return res.render("staticPage/Terms&Conditions.njk");
});

app.use((req, res) => {
  console.log(`Path not found: ${req.url}`);
  return res.render("staticPage/404.njk");
});

const port = 3030;

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
