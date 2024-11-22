const express = require('express');
const router = express.Router();
const authService = require('./auth.service');
const jwt = require('jsonwebtoken');

router.post('/register', async (req, res, next) => {

    const { username, email, password } = req.body;
    try {

        const newUser = await authService.register(username, email, password);

        res.status(201).json({ data: { username: newUser.username, email: newUser.email }, message: "Registration Success!" });

    } catch (error) {

        res.status(400).json({ error: error.message });

    }

});

router.post('/login', async (req, res, next) => {

    const { username, password } = req.body;

    try {

        const { user, token } = await authService.login(username, password); // Menambahkan variable “token”

        res.status(200).json({ data: { username: user.username, token }, message: "Login Success!" }); // Menambahkan property “token”

    } catch (error) {

        res.status(400).json({ error: error.message });

    }


});

function generateToken(user) {

    return jwt.sign({ userId: user.id, username: user.username, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

}

module.exports = router;

