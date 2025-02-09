import crypto from "crypto";

const SECRET_TOKEN = process.env.SECRET_TOKEN || "f";

export const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  console.log(`Received token: ${token}`);
  const hash = crypto.createHash("sha256").update(SECRET_TOKEN).digest("hex");
  if (token === hash) {
    console.log("Authentication successful");
    next();
  } else {
    console.log("Authentication failed");
    res.status(401).send("Unauthorized");
  }
};



