import xss from "express-xss-sanitizer";

export const sanitizeXSS = xss({
  whiteList: [],
  stripIgnoreTag: true,
  stripIgnoreTagBody: ["script"],
});
