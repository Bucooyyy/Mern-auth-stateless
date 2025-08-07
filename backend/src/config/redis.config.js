import { createClient } from "redis";

const redisClient = createClient({
  username: process.env.REDIS_USERNAME,
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_URL,
    port: process.env.REDIS_PORT,
  },
});

redisClient.on("connect", () => console.log(`Redis client connected on: ${process.env.REDIS_URL}:${process.env.REDIS_PORT}`));
redisClient.on("error", (error) => console.log("Redis client error", error));

export const connectRedis = async () => {
  try {
    await redisClient.connect();
  } catch (error) {
    console.log("Redis connection error:", error);
  }
};

export default redisClient;
