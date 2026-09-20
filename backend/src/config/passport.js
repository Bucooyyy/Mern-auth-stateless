import passport from "passport";
import pkg from "passport-jwt";
const { Strategy: JwtStrategy, ExtractJwt } = pkg;
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GithubStrategy } from "passport-github2";

import bcrypt from "bcrypt";
import User from "../models/user.model.js";
import logger, { logSecurityEvent } from "../config/winston.logger.js";
import { isTokenBlacklisted } from "../utils/tokenjwt.js";

// ─── Helper: find-or-create an OAuth user ─────────────────────────────────────
/**
 * Handles the common pattern for all OAuth providers:
 * 1. Find user by providerId.
 * 2. If not found, find by email (link account) or create new user.
 */
const handleOAuthUser = async ({ provider, providerId, email, name, avatar, reqIp = null, userAgent = null }) => {
  const oauthField = `oauth.${provider}Id`;

  let user = await User.findOne({ [oauthField]: providerId });
  if (user) {
    logSecurityEvent("OAUTH_LOGIN_SUCCESS", user._id, reqIp, userAgent, {
      provider,
      email: user.email,
    });
    logger.info("OAuth login: user successfully logged in", { provider, UserId: user._id });
    return user;
  }

  if (email) {
    user = await User.findOne({ email });
    if (user) {
      user.oauth[`${provider}Id`] = providerId;
      if (!user.avatar && avatar) user.avatar = avatar;
      await user.save();
      logSecurityEvent("OAUTH_ACCOUNT_LINKED", user._id, reqIp, userAgent, {
        provider,
        email,
      });
      logger.info("OAuth account linked to existing user", { provider, UserId: user._id, email: user.email });
      return user;
    }
  }

  const newUserData = {
    name: name || `${provider}_${providerId}`,
    email: email || `${provider}_${providerId}@oauth.placeholder`,
    isAccountVerified: !!email, //Trust OAuth provider's email verification
    avatar: avatar || null,
    oauth: { [`${provider}Id`]: providerId },
  };

  user = await User.create(newUserData);
  logSecurityEvent("OAUTH_USER_CREATED", user._id, reqIp, userAgent, {
    provider,
    email: user.email,
  });
  logger.info("New OAuth user created", { provider, UserId: user._id, email: user.email });
  return user;
};

// ─── JWT Strategy ───────────────────────────────────────────────────────────────
/**
 * Configures the JWT strategy for Passport.
 * It extracts the token from either the Authorization header or the accessToken cookie.
 * @param {import('express').Request} req - The Express request object.
 * @param {object} payload - The decoded JWT payload.
 * @param {function} done - The callback function to resolve the authentication.
 */
passport.use(
  "jwt",
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromExtractors([ExtractJwt.fromAuthHeaderAsBearerToken(), (req) => req?.cookies?.accessToken || null]),
      secretOrKey: process.env.JWT_ACCESS_SECRET,
      passReqToCallback: true,
    },
    async (req, payload, done) => {
      try {
        const authHeader = req.headers.authorization;
        let token = null;

        if (authHeader && authHeader.startsWith("Bearer ")) {
          token = authHeader.split(" ")[1];
        } else if (req.cookies && req.cookies.accessToken) {
          token = req.cookies.accessToken;
        }

        if (!token) {
          logSecurityEvent("MISSING_TOKEN", null, req.ip, req.headers["user-agent"], {
            path: req.originalUrl,
            reason: "No auth token in header or cookie",
          });
          return done(null, false, { message: "No auth token" });
        }

        const isBlackListed = await isTokenBlacklisted(token);
        if (isBlackListed) {
          logSecurityEvent("BLACKLISTED_TOKEN", payload.userId, req.ip, req.headers["user-agent"], {
            path: req.originalUrl,
          });
          return done(null, false);
        }

        const user = await User.findById(payload.userId);

        if (!user) {
          logSecurityEvent("USER_NOT_FOUND", payload.userId, {
            path: req.originalUrl,
            userId: payload.userId,
          });
          return done(null, false);
        }

        return done(null, user);
      } catch (error) {
        logger.error("ERROR_IN_JWT_STRATEGY", {
          error: error.message,
          stack: error.stack,
          path: req.originalUrl,
        });
        return done(error, false);
      }
    },
  ),
);

// ─── Local Strategy ─────────────────────────────────────────────────────────────
passport.use(
  "local",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email }).select("+password");

        if (!user || !user.password) {
          return done(null, false, { message: "Invalid credentials" });
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
          return done(null, false, { message: "Invalid credentials" });
        }

        logger.info("User login via local strategy", { userId: user._id, email: user.email });

        return done(null, user);
      } catch (error) {
        logger.error("ERROR_IN_LOCAL_STRATEGY", {
          error: error.message,
          stack: error.stack,
        });
        return done(error);
      }
    },
  ),
);

// ─── Google Strategy ───────────────────────────────────────────────────────────
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true,
    },
    async (req, _accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const user = await handleOAuthUser({
          provider: "google",
          providerId: profile.id,
          email,
          name: profile.displayName,
          avatar: profile.photos?.[0]?.value,
          reqIp: req.ip,
          userAgent: req.headers["user-agent"],
        });
        return done(null, user);
      } catch (error) {
        logger.error("ERROR_IN_GOOGLE_STRATEGY", {
          error: error.message,
          stack: error.stack,
          profileId: profile?.id,
        });
        return done(error);
      }
    },
  ),
);

// ─── Github Strategy ──────────────────────────────────────────────────────────
passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
      scope: ["user:email"],
      passReqToCallback: true,
    },
    async (req, _accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const user = await handleOAuthUser({
          provider: "github",
          providerId: profile.id,
          email,
          name: profile.displayName || profile.username,
          avatar: profile.photos?.[0]?.value,
          reqIp: req.ip,
          userAgent: req.headers["user-agent"],
        });
        return done(null, user);
      } catch (error) {
        logger.error("ERROR_IN_GITHUB_STRATEGY", {
          error: error.message,
          stack: error.stack,
          profileId: profile?.id,
        });
        return done(error);
      }
    },
  ),
);

export default passport;
