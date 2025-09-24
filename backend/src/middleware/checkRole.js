const checkRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Authentication required." });
    }

    const userRoles = req.user.roles;
    const hasRole = userRoles.some((role) => allowedRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({ message: "Unauthorized: Insufficient role." });
    }

    next();
  };
};

export default checkRole;
