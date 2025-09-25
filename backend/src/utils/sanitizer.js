import xss from "xss";

export const sanitizeInput = (value, options = {}) => {
  if (typeof value !== "string") return value;

  const { context = "body", allowLinks = false, allowImages = false } = options;

  if (context === "password" || context === "token") {
    return value;
  }

  if (context === "email") {
    return value.toLowerCase().trim();
  }

  const xssOptions = {
    whiteList: {
      // ...(allowLinks && { a: ["href", "title", "rel"] }),
      // ...(allowImages && { img: ["src", "alt", "width", "height"] }),
      ...(context === "body" && {
        b: [],
        i: [],
        strong: [],
        em: [],
        u: [],
        p: [],
        br: [],
        ul: [],
        ol: [],
        li: [],
        blockquote: [],
        code: [],
        pre: [],
      }),
    },
    stripIgnoreTag: true,
    escapeHtml: (html) => {
      if (context === "attribute") {
        return html.replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/</g, "<").replace(/>/g, ">");
      }
      return html;
    },
  };
  return xss(value.trim(), xssOptions);
};

export const sanitizeObject = (obj, options = {}) => {
  if (typeof obj !== "object" || obj === null) return;

  Object.keys(obj).forEach((key) => {
    if (obj[key] && typeof obj[key] === "string") {
      obj[key] = sanitizeInput(obj[key], options);
    } else if (typeof obj[key] === "object") {
      sanitizeObject(obj[key], options);
    }
  });
};
