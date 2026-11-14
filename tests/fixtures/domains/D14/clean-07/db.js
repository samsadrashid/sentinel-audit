module.exports = (db, id) => db.query('SELECT * FROM t WHERE id = $1', [id]);
