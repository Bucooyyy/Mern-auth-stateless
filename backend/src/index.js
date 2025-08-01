import express, { urlencoded } from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import passport from "passport";
import rateLimit from "express-rate-limit";
import { connectDB } from "./lib/db.js";
import authRoutes from "./routes/auth.route.js";

import "./lib/passportjs/jwt.passport.js";
const app = express();

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60_000,
  max: 10,
});

// Middlewares
app.use(express.json({ authLimiter })); // allows us to parse incoming requests: req.body
app.use(urlencoded({ authLimiter, extended: true }));
app.use(cookieParser({ secret: process.env.COOKIE_PARSER })); // // allows us to parse incoming cookies
app.use(cors({ credentials: true }));
app.use(passport.initialize());

// Routes
app.use("/api/auth", authRoutes);

//  Port and DB Connection
const port = process.env.PORT || 5000;
connectDB();
try {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
} catch (error) {
  console.error("Error while starting the server:", error);
}
