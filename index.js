import express from "express";
import path from "path";
import { fileURLToPath } from "url"; 
import dotenv from "dotenv"; // Updated to use import
import mainRoutes from "./routes/main.js";
import { pool } from "./routes/pool.js"; // Import the pool
import { engine } from "express-handlebars"; // Import Handlebars
import Handlebars from "handlebars"; 

dotenv.config(); // Use dotenv to load environment variables
const app = express();
app.use(express.json()); // To parse JSON request bodies

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
Handlebars.registerHelper('eq', function (a, b) {
  return a === b;
});
Handlebars.registerHelper('encodeURIComponent', function (str) {
  return encodeURIComponent(str);
});
// Configure Handlebars
app.engine("handlebars", engine({
  defaultLayout: false,
  partialsDir: [
    path.join(__dirname, "views/templates"),
    path.join(__dirname, "views/notice"),
    path.join(__dirname, "views")
  ],  cache: false // Disable cache for development

}));
app.set("view engine", "handlebars");
app.set("views", path.join(__dirname, "views"));


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

app.use('/Assets/Images', express.static(path.join(__dirname, 'Assets'), {
  maxAge: '1d' // Cache assets for 1 day
}));

// return res.render("");
// render load page from views folder

app.get("/", (req, res) => {
  return res.render("staticPage/index"); // Ensure the file extension is .handlebars 
 });

app.get("/login", (req, res) => {
  if (req.session && req.session.user) {
    return res.render("staticPage/login", { userLoggedIn: true });
  }
  return res.render("staticPage/login");
});

app.get("/Terms&Conditions", (req, res) => {
  return res.render("staticPage/Terms&Conditions");
});

app.get("/FAQs", async (req, res) => {
  res.render("staticPage/FAQs");
});

app.get("/Credits", async (req, res) => {
  res.render("staticPage/Credits");
});



app.get('/simulate-error', (req, res, next) => {
  next(new Error('Simulated server error'));
});

app.use((req, res) => {
  console.log(`Path not found: ${req.url}`);
  return res.render("staticPage/404");
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500);
  res.render('templates/Error/500', { error: err });
});

const port = 3333;

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
