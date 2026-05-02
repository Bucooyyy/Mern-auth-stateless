import Redis from "ioredis";
import logger from "../config/winston.logger.js";

let redisClient;

/**
 * Returns a singleton Redis client.
 * Lazy-initialised on first call.
 */
export const getRedisClient = () => {
  if (redisClient) return redisClient;

  redisClient = new Redis(process.env.REDIS_URI, {
    retryStrategy: (times) => Math.min(times * 100, 3000),
    maxRetriesPerRequest: null, // let ioredis handle retries
  });

  redisClient.on("connect", () => logger.info("Redis connected"));
  redisClient.on("error", (err) => logger.error("Redis error", { error: err.message }));
  redisClient.on("reconnecting", () => logger.warn("Redis reconnecting..."));

  return redisClient;
};
