import passport from "passport";
import pkg from "passport-jwt";
const { Strategy: JwtStrategy, ExtractJwt } = pkg;
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GithubStrategy } from "passport-github2";
import { Strategy as TwitterStrategy } from "passport-twitter";

import bcrypt from "bcrypt";
import User from "../../models/user.model.js";
import logger from "../../config/winston.logger.js";

// ─── Helper: find-or-create an OAuth user ─────────────────────────────────────
/**
 * Handles the common pattern for all OAuth providers:
 * 1. Find user by providerId.
 * 2. If not found, find by email (link account) or create new user.
 */
const handleOAuthUser = async ({ provider, providerId, email, name, avatar }) => {
  const oauthField = `oauth.${provider}Id`;

  let user = await User.findOne({ [oauthField]: providerId });
  if (user) return user;

  if (email) {
    user = await User.findOne({ email });
    if (user) {
      user.oauth[`${provider}Id`] = providerId;
      if (!user.avatar && avatar) user.avatar = avatar;
      await user.save();
      logger.info("OAuth account linked to existing user", { provider, email });
      return user;
    }
  }

  user = await User.create({
    name: name || `user_${providerId}`,
    email: email || `${provider}_${providerId}@oauth.placeholder`,
    isAccountVerified: !!email, //Trust OAuth provider's email verification
    avatar,
    oauth: { [`${provider}Id`]: providerId },
  });

  logger.info("New OAuth user created", { email, provider });
  return user;
};

// ─── JWT Strategy ───────────────────────────────────────────────────────────────
passport.use(
  "jwt",
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_ACCESS_SECRET,
    },
    async (payload, done) => {
      try {
        const user = await User.findById(payload.userId);
        if (!user) return done(null, false);
        return done(null, user);
      } catch (error) {
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
        if (!match) return done(null, false, { message: "Invalid credentials" });
        return done(null, user);
      } catch (error) {
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
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const user = await handleOAuthUser({
          provider: "google",
          providerId: profile.id,
          email,
          name: profile.displayName,
          avatar: profile.photos?.[0]?.value,
        });
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    },
  ),
);

// ─── Discord Strategy ──────────────────────────────────────────────────────────
passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_CALLBACK_URL,
      scope: ["identify", "email"],
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.email;
        const avatar = profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null;
        const user = await handleOAuthUser({
          provider: "discord",
          providerId: profile.id,
          email,
          name: profile.username,
          avatar,
        });
        return done(null, user);
      } catch (error) {
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
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const user = await handleOAuthUser({
          provider: "github",
          providerId: profile.id,
          email,
          name: profile.displayName || profile.username,
          avatar: profile.photos?.[0]?.value,
        });
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    },
  ),
);

// ─── Twitter Strategy ──────────────────────────────────────────────────────────
passport.use(
  new TwitterStrategy(
    {
      consumerKey: process.env.TWITTER_CONSUMER_KEY,
      consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
      callbackURL: process.env.TWITTER_CALLBACK_URL,
      includeEmail: true,
    },
    async (_token, _tokenSecret, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const user = await handleOAuthUser({
          provider: "twitter",
          providerId: profile.id,
          email,
          name: profile.displayName,
          avatar: profile.photos?.[0]?.value?.replace("_normal", ""),
        });
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    },
  ),
);

export default passport;
