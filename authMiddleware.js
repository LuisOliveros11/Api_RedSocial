const jwt = require('jsonwebtoken');
require('dotenv').config();

function authenticateToken(req, res, next) {
    //Formato "Bearer <token>"
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ message: "Error. Token no proporcionado." });
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: "Error. Token inválido o expirado." });
      req.user = user; // Si es válido, se guarda la info en req.user
      next();
    });
  }
  
  module.exports = { authenticateToken };