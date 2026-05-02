import mongoose from "mongoose";
import logger from "./winston.logger.js";

export const connectDB = async () => {
  try {
    const dbClient = await mongoose.connect(process.env.MONGODB_URI, {
      maxPoolSize: 10, // Set the maximum pool size to 10
    });
    logger.info(`MongoDB connected on: ${dbClient.connection.host}`);

    mongoose.connection.on("disconnected", () => {
      logger.warn("MongoDB disconnected - retrying connection...");
    });

    mongoose.connection.on("error", (err) => {
      logger.error("MongoDB connection error:", { error: err.message });
    });
  } catch (err) {
    logger.error("Failed to connect to MongoDB", { error: err.message });
    process.exit(1); // Exit the process with failure code
  }
};
