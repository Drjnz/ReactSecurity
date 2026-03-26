const fs = require('fs');

function logSecurityEvent(message) {
  const line = `${new Date().toISOString()} — ${message}\n`;
  fs.appendFile('security.log', line, err => {
    if (err) console.error('Erreur écriture log :', err);
  });
}

module.exports = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }

  logSecurityEvent(`ADMIN_INTRUSION userId=${req.user?.id}`);

  return res.status(403).json({ error: "Accès réservé aux administrateurs" });
};