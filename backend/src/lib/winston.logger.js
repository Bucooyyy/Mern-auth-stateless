import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LOG_DIR = path.join(__dirname, "../../logs");

const maskSensitive = winston.format((info) => {
  const SENSITIVE_KEYS = ["password", "secret", "token", "refreshToken", "accessToken"];

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
    const extras = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : "";
    return `[${timestamp}] ${level}: ${message}${extras}`;
  }),
);

const fileFormat = winston.format.combine(maskSensitive(), winston.format.timestamp(), winston.format.json());

const errorRotate = new DailyRotateFile({
  dirname: LOG_DIR,
  filename: "error-%DATE%.log",
  datePattern: "YYYY-MM-DD",
  level: "error",
  maxFiles: "30d",
  format: fileFormat,
});

const combinedRotate = new DailyRotateFile({
  dirname: LOG_DIR,
  filename: "combined-%DATE%.log",
  datePattern: "YYYY-MM-DD",
  maxFiles: "14d",
  format: fileFormat,
});

const logger = winston.createLogger({
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  transports: [errorRotate, combinedRotate],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(new winston.transports.Console({ format: consoleFormat }));
}

const dailyRotateFileTransport = new winston.transports.DailyRotateFile({
  filename: "logs/security-%DATE%.log",
  datePattern: "YYYY-MM-DD",
  zippedArchive: true,
  maxSize: "20m",
  maxFiles: "14d",
});

const securityLogger = winston.createLogger({
  level: "info",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [dailyRotateFileTransport, new winston.transports.Console()],
});

export const logSecurityEvent = (event, userId, ip, userAgent) => {
  securityLogger.info({
    event,
    userId,
    ip,
    userAgent,
    timestamp: new Date().toISOString(),
  });
};
