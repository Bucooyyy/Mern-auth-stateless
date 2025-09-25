import express, { urlencoded } from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import passport from "./lib/passport-strategies/jwt.passport.js";
import authRoutes from "./routes/auth.route.js";

import "./lib/passport-strategies/jwt.passport.js";
import { connectDB } from "./config/db.config.js";
import { connectRedis } from "./config/redis.config.js";
import { authLimiter, loginLimiter, MFAlimiter } from "./middleware/rateLimiter.js";

const app = express();

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
connectRedis();
try {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
} catch (error) {
  console.error("Error while starting the server:", error);
}
