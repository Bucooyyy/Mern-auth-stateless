import express, { urlencoded } from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import helmet from "helmet";
// import mongoSanitize from "express-mongo-sanitize";
import morgan from "morgan";
import passport from "./config/passport.js";
import authRoutes from "./routes/auth.route.js";
import swaggerUi from "swagger-ui-express";
import { swaggerSpec } from "./config/swagger.config.js";

import { connectDB } from "./config/db.config.js";
import { getRedisClient } from "./config/redis.config.js";
import { generalLimiter } from "./middleware/rateLimiter.js";
import errorHandler from "./middleware/errorHandler.js";

const app = express();

// Middlewares
// app.use(generalLimiter);
// app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(helmet()); // Secure HTTP headers
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev")); // HTTP request logger
app.use(express.json({ limit: "10kb" })); // parse incoming requests with JSON payloads
app.use(urlencoded({ extended: true, limit: "10kb" })); // parse incoming requests with urlencoded payloads
app.use(cookieParser({ secret: process.env.COOKIE_PARSER })); // parse incoming cookies
app.use(cors({ credentials: true, origin: process.env.FRONTEND_URL || "http://localhost:5173" }));
app.use(passport.initialize());

// Routes
app.use("/api/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use("/api/auth", authRoutes);

//  Port and DB Connection
const port = process.env.PORT || 5000;
connectDB();
getRedisClient();

app.use(errorHandler);
try {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
} catch (error) {
  console.error("Error while starting the server:", error);
}
