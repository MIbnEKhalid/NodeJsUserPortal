import pkg from "pg";
const { Pool } = pkg;
import dotenv from "dotenv"; // Updated to use import

dotenv.config(); // Use dotenv to load environment variables

// PostgreSQL connection pool
const poolConfig = process.env.IsDeployed === "true" ? {
  connectionString: process.env.NEON_POSTGRES,
  ssl: {
    rejectUnauthorized: true,
  },
} : {
  connectionString: process.env.LOCAL_POSTGRES,
};

export const pool = new Pool(poolConfig);

// Test connection
(async () => {
  try {
    const client = await pool.connect();
    const dbName = process.env.IsDeployed === "true" ? "Neon" : "local";
    console.log("Connected to " + dbName + " PostgreSQL database!");
    client.release();
  } catch (err) {
    console.error("Database connection error:", err);
  }
})(); 