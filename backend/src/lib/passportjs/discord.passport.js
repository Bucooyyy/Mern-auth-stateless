import passport from "passport";
import DiscordStrategy from "passport-discord";
import user from "../../models/user.model.js";
import { refreshToken } from "../tokenjwt.js";
