module.exports = (db, id) => db.query('SELECT * FROM t WHERE id = ' + id);
