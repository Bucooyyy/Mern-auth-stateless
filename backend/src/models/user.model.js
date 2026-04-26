import mongoose from "mongoose";

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
    toJSON: {
      transform: function (_doc, ret) {
        delete ret.password;
        if (ret.MFA) delete ret.MFA.secret;
        delete ret.refreshTokens;
        return ret;
      },
    },
  },
);

userSchema.index({ "oauth.googleId": 1 }, { sparse: true });
userSchema.index({ "oauth.githubId": 1 }, { sparse: true });
userSchema.index({ "oauth.twitterId": 1 }, { sparse: true });
userSchema.index({ "oauth.discordId": 1 }, { sparse: true });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ emailVerificationToken: 1 }, { sparse: true });
userSchema.index({ resetPasswordToken: 1 }, { sparse: true });

const User = mongoose.models.User || mongoose.model("User", userSchema);

export default User;
