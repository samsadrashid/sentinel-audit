module.exports = (col, expr) => col.find({ '$where': expr });
