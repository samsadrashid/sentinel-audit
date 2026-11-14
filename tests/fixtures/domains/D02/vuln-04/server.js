const cors = require('cors');
const app = require('express')();
app.use(cors({ origin: '*', credentials: true }));
