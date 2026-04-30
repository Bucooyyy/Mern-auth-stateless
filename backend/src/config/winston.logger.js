import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LOG_DIR = path.join(__dirname, "../../logs");

const SENSITIVE_KEYS = ["password", "secret", "token", "refreshToken", "accessToken", "authorization", "pin"];

const maskSensitive = winston.format((info) => {
  if (info.meta && typeof info.meta === "object") {
    info.meta = Object.fromEntries(
      Object.entries(info.meta).map(([key, value]) => {
        if (SENSITIVE_KEYS.has(key.toLowerCase())) {
          return [key, "[REDACTED]"];
        }
        return [key, value];
      }),
    );
  }
  return info;
});

const consoleFormat = winston.format.combine(
  maskSensitive(),
  winston.format.colorize(),
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const extras = Object.keys(meta).length ? `\nData: ${JSON.stringify(meta, null, 2)}` : "";
    return `[${timestamp}] ${level}: ${message}${extras}`;
  }),
);

const fileFormat = winston.format.combine(maskSensitive(), winston.format.timestamp(), winston.format.json());

const errorRotate = new DailyRotateFile({
  dirname: LOG_DIR,
  filename: "error-%DATE%.log",
  datePattern: "YYYY-MM-DD",
  level: "error",
  maxSize: "20m",
  maxFiles: "30d",
  zippedArchive: true,
  format: fileFormat,
});

const combinedRotate = new DailyRotateFile({
  dirname: LOG_DIR,
  filename: "combined-%DATE%.log",
  datePattern: "YYYY-MM-DD",
  maxSize: "20m",
  maxFiles: "14d",
  zippedArchive: true,
  format: fileFormat,
});

const logger = winston.createLogger({
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  transports: [errorRotate, combinedRotate],
  exitOnError: false,
});

if (process.env.NODE_ENV !== "production") {
  logger.add(new winston.transports.Console({ format: consoleFormat }));
}

export default logger;
