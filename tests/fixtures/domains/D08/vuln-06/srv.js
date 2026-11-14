const fs = require('fs');
module.exports = (req, res) => res.send(fs.readFileSync(req.query.file));
