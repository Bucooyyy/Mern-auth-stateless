import { sanitizeInput } from "../../utils/sanitizer.js";
import securityConfig from "../../config/security.config.js";

export const parsePrompt = (input) => {
  if (typeof input === "string") {
    return {
      type: "text",
      text: sanitizeInput(input, securityConfig.XSS_POLICIES.PROMPT),
      parameters: {},
    };
  }

  if (typeof input === "object" && input !== null) {
    if (input.text) {
      return {
        type: "structured",
        text: sanitizeInput(input.text, securityConfig.XSS_POLICIES.PROMPT),
        parameters: parsePromptParameters(input.parameters || {}),
      };
    }

    if (input.prompt) {
      return {
        type: "advanced",
        text: sanitizeInput(input.prompt, securityConfig.XSS_POLICIES.PROMPT),
        parameters: parsePromptParameters({
          ...input.parameters,
          ...(input.negativePrompt && { negativePrompt: input.negativePrompt }),
          ...(input.stylePrompt && { stylePrompt: input.stylePrompt }),
          ...(input.aspectRatio && { aspectRatio: input.aspectRatio }),
          ...(input.seed && { seed: input.seed }),
        }),
      };
    }
  }
  throw new Error("Invalid prompt format");
};
const parsePromptParameters = (params) => {
  const validated = {};

  if (params.negativePrompt) {
    validated.negativePrompt = sanitizeInput(params.negativePrompt, securityConfig.XSS_POLICIES.PROMPT);
  }

  if (params.stylePrompt) {
    validated.stylePrompt = sanitizeInput(params.stylePrompt, securityConfig.XSS_POLICIES.PROMPT);
  }

  if (params.aspectRatio) {
    const validRatios = ["1:1", "16:9", "9:16", "4:3", "3:4", "21:9"];
    const ratio = String(params.aspectRatio).toLowerCase();

    if (validRatios.includes(ratio)) {
      validated.aspectRatio = ratio;
    } else {
      const [width, height] = ratio.split(":");
      if (width && height && !isNaN(width) && !isNaN(height)) {
        const gcd = (a, b) => (b ? gcd(b, a % b) : a);
        const divisor = gcd(width, height);
        validated.aspectRatio = `${width / divisor}:${height / divisor}`;
      }
    }
  }

  if (params.seed !== undefined) {
    const seed = Number(params.seed);
    if (!isNaN(seed) && seed >= 0 && seed <= 4294967295) {
      validated.seed = Math.floor(seed);
    }
  }

  if (params.styleModifiers) {
    if (Array.isArray(params.styleModifiers)) {
      validated.styleModifiers = params.styleModifiers.filter((mod) => typeof mod === "string").slice(0, 5);
    }
  }

  if (params.colorPalette) {
    if (Array.isArray(params.colorPalette)) {
      validated.colorPalette = params.colorPalette.filter((color) => /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(color)).slice(0, 5);
    }
  }
};

export const toApiFormat = (parsed) => {
  return {
    prompt: parsed.text,
    ...(parsed.parameters.negativePrompt && { negative_Prompt: parsed.parameters.negativePrompt }),
    ...(parsed.parameters.stylePrompt && { style_Prompt: parsed.parameters.stylePrompt }),
    ...(parsed.parameters.aspectRatio && { aspect_Ratio: parsed.parameters.aspectRatio }),
    ...(parsed.parameters.seed !== undefined && { seed: parsed.parameters.seed }),
    ...(parsed.parameters.styleModifiers && { style_Modifiers: parsed.parameters.styleModifiers }),
    ...(parsed.parameters.colorPalette && { color_Palette: parsed.parameters.colorPalette }),
  };
};
