import { body, param } from "express-validator";

export const validateEmailVerification = [
  param("token")
    .isLength({ min: 64, max: 64 })
    .withMessage("Invalid verification token format")
    .matches(/^[a-f0-9]{64}$/)
    .withMessage("Verification token must be a valid hexadecimal string"),
];

// export const validateResendEmailVerification = [
//   emailValidation
// ];

export const validateImageGeneration = [
  body("prompt")
    .notEmpty()
    .withMessage("Image prompt is required")
    .isLength({ min: 3, max: 1000 })
    .withMessage("Prompt must be between 3 and 1000 characters long")
    .custom((value) => {
      // Check for inappropriate content
      const inappropriateWords = [
        "nude",
        "naked",
        "sex",
        "porn",
        "violence",
        "gore",
        "blood",
        "kill",
        "death",
        "suicide",
        "drug",
        "weapon",
        "bomb",
        "terrorist",
      ];

      const lowerPrompt = value.toLowerCase();
      for (const word of inappropriateWords) {
        if (lowerPrompt.includes(word)) {
          throw new Error("Prompt contains inappropriate content");
        }
      }
      return true;
    }),

  body("style").optional().isIn(["realistic", "artistic", "cartoon", "abstract", "vintage", "modern"]).withMessage("Invalid style selected"),

  body("size").optional().isIn(["256x256", "512x512", "1024x1024"]).withMessage("Invalid image size"),

  body("quality").optional().isIn(["standard", "hd"]).withMessage("Invalid Image quality"),

  body("numberOfImages").optional().isInt({ min: 1, max: 4 }).withMessage("Number of images must be between 1 and 4"),
];
