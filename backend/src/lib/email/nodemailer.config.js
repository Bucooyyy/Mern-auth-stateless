import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Test the connection
transporter.verify((error, success) => {
  if (error) {
    console.error("Error connecting to SMTP server:", error);
  } else {
    console.log("SMTP server is ready to send emails.");
  }
});

export default transporter;
