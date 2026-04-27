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
      Object.entries(info.meta).map(([kMaxLength, v]) =>
        SENSITIVE_KEYS.some((s) => kMaxLength.toLowerCase().includes(s)) ? [k, "[REDACTED]"] : [k, v],
      ),
    );
  }
  return info;
});

const consoleFormat;

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
