/**
 * Seed Script – creates an initial admin user.
 *
 * Usage:
 *   node admin.seed.js
 *
 * Reads credentials from environment variables (or .env):
 *   ADMIN_NAME     – display name     (default: "Admin")
 *   ADMIN_EMAIL    – email address    (default: "admin@yourapp.com")
 *   ADMIN_PASSWORD – plain password   (default: "Admin@123456")
 *
 * Safe to run multiple times: it will update the existing admin rather than
 * creating a duplicate.
 */

import "dotenvconfig";
import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: function () {
        return !this.oauth || !Object.values(this.oauth).some(Boolean);
      },
      minlength: 8,
      select: false,
    },
    roles: {
      type: String,
      enum: ["free", "premium", "admin"],
      default: "free",
    },
    avatar: {
      type: String,
      default: null,
    },
    // Email Verif
    isAccountVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: {
      type: String,
      select: false,
    },
    emailVerificationTokenExpires: {
      type: Date,
      default: null,
    },
    // Pass Reset
    resetPasswordToken: {
      type: String,
      select: false,
    },
    resetPasswordTokenExpires: {
      type: Date,
      default: null,
    },
    // MFA
    isMFAEnabled: {
      type: Boolean,
      required: false,
    },
    MFA: {
      secret: { type: String, select: false }, //Secret permanen setelah terverifikasi
      tempSecret: { type: String, select: false }, // Secret sementara saat proses setup
      qrCodeUrl: { type: String, default: null },
      enabled: { type: Boolean, default: false },
    },
    oauth: {
      googleId: { type: String, default: null },
      githubId: { type: String, default: null },
      twitterId: { type: String, default: null },
      discordId: { type: String, default: null },
    },
    refreshTokens: {
      type: [String],
      select: false,
      default: [],
    },
  },
  {
    timestamps: true,
  },
);

const User = mongoose.models.User || mongoose.model("User", userSchema);

//---------------- Seed ------------
const seed = async () => {
  const MONGODB_URI = process.env.MONGODB_URI;
  if (!MONGODB_URI) {
    console.error("❌  MONGO_URI is not set. Copy .env.example to .env and configure it.");
    process.exit(1);
  }
  await mongoose.connect(MONGODB_URI);
  console.log("✅  Connected to MongoDB");

  const name = process.env.ADMIN_NAME || "Admin";
  const email = process.env.ADMIN_EMAIL || "admin@myapp.com";
  const password = process.env.ADMIN_PASSWORD || "AdminMyApp@123456";

  const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS) || 12;
  const strongPassword = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{8,}$/;
  if (!strongPassword.test(password)) {
    console.error("❌  ADMIN_PASSWORD is too weak. It must be ≥8 chars with uppercase, number, and special char.");
    await mongoose.disconnect();
    process.exit(1);
  }

  const hash = await bcrypt.hash(password, saltRounds);

  const admin = await User.findOneAndUpdate(
    { email },
    {
      $set: {
        name,
        email,
        password: hash,
        role: "admin",
        isAccountVerified: true,
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  );

  console.log(`✅  Admin user seeded successfully:`);
  console.log(`    ID    : ${admin._id}`);
  console.log(`    Name  : ${admin.name}`);
  console.log(`    Email : ${admin.email}`);
  console.log(`    Role  : ${admin.role}`);
  console.log("\n⚠️   Change the admin password after first login!\n");

  await mongoose.disconnect();
  process.exit(0);
};

seed().catch((err) => {
  console.error("❌  Seed failed:", err.message);
  process.exit(1);
});
