const express = require('express');
const router = express.Router();

const authCont = require('../controllers/auth');

router.post('/register', authCont.createUser);

module.exports = router;