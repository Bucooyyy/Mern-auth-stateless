import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: function () {
        return !this.oauth;
      },
      minlength: 8,
      select: false,
    },
    roles: {
      type: String,
      enum: ["freeUser", "premiumUser"],
      default: "freeUser",
    },
    avatar: {
      type: String,
      default: null,
    },
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
    resetPasswordToken: {
      type: String,
      select: false,
    },
    resetPasswordTokenExpires: {
      type: Date,
      default: null,
    },
    isMFAEnabled: {
      type: Boolean,
      required: false,
    },
    MFA: {
      secret: { type: String, select: false }, //Secret permanen setelah terverifikasi
      tempSecret: { type: String, select: false }, // Secret sementara saat proses setup
      qrCodeUrl: { type: String },
      enabled: { type: Boolean, default: false },
    },
    oauth: { googleId: String, githubId: String, twitterId: String, discordId: String },
  },
  {
    timestamps: true,
    toJSON: {
      transform: function (doc, ret) {
        delete ret.password;
        delete ret.MFA.secret;
        return ret;
      },
    },
  }
);

userSchema.index({ "oauth.googleId": 1 }, { sparse: true });
userSchema.index({ "oauth.githubId": 1 }, { sparse: true });
userSchema.index({ "oauth.twitterId": 1 }, { sparse: true });
userSchema.index({ "oauth.discordId": 1 }, { sparse: true });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

const userModel = mongoose.models.User || mongoose.model("User", userSchema);

export default userModel;
