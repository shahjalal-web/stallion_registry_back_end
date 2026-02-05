const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Forbidden" });
    req.user = decoded;
    next();
  });
};

// 🔥 DB injected middleware
const verifyAdmin = (userCollection) => {
  return async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader)
        return res.status(401).send({ message: "Unauthorized" });

      const token = authHeader.split(" ")[1];

      jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err)
          return res.status(403).send({ message: "Invalid token" });

        if (decoded.role !== "admin")
          return res.status(403).send({ message: "Admins only" });

        const admin = await userCollection.findOne({
          _id: new ObjectId(decoded.userId),
          role: "admin",
        });

        if (!admin)
          return res.status(403).send({ message: "Admin not found" });

        req.user = decoded;
        next();
      });
    } catch (err) {
      res.status(500).send({ message: "Server error" });
    }
  };
};

module.exports = { verifyJWT, verifyAdmin };
