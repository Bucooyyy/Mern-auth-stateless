import { validationResult } from "express-validator";

export const validationHandler = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map((error) => ({
      field: error.param,
      message: error.msg,
      location: error.location,
    }));
    return res.status(400).json({
      success: false,
      message: "Validation errors found",
      errors: formattedErrors,
    });
  }
  next();
};
