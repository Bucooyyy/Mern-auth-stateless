export const sendSuccess = (res, statusCode = 200, message = "OK", data = null) => {
  const body = { success: true, message };
  if (data !== null) body.data = data;
  return res.status(statusCode).json(body);
};
export const sendError = (res, statusCode = 500, message = "Error", errors = null) => {
  const body = { success: false, message };
  if (errors !== null) body.errors = errors;
  return res.status(statusCode).json(body);
};
