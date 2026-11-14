const cors = require('cors');
const app = require('express')();
app.use(cors({ origin: 'https://app.example.org', credentials: true }));
