import winston from "winston";
import "winston-daily-rotate-file";

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

const logSecurityEvent = (event, userId, ip, userAgent) => {
  securityLogger.info({
    event,
    userId,
    ip,
    userAgent,
    timestamp: new Date().toISOString(),
  });
};
