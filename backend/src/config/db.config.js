import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    const dbClient = await mongoose.connect(process.env.MONGODB_URI);
    console.log(`MongoDB connected on: ${dbClient.connection.host}`);
  } catch (error) {
    console.log("MongoDB connection error:", error);
  }
};
