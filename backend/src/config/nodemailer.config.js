import nodemailer from "nodemailer";
import logger from "../config/winston.logger.js";

let _transport;

export const getTransporter = async () => {
  if (_transport) return _transport;

  _transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  try {
    await _transport.verify();
    logger.info("SMTP transport ready");
  } catch (error) {
    logger.error("Failed to verify SMTP transport", { error: error.message });
  }
  return _transport;
};

export default getTransporter;
