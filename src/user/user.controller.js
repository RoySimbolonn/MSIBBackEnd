const express = require('express');
const router = express.Router();
const userService = require('./user.service');

// Create User
router.post("/", async (req, res) => {
    try {
        const userData = req.body;
        const newUser = await userService.createUser(userData);
        res.status(201).json(newUser);
    } catch (error) {
        res.status(400).send(error.message);
    }
});

// Get All Users
router.get("/", async (req, res) => {
    try {
        const users = await userService.getAllUsers();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Get User by ID
router.get("/:id", async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const user = await userService.getUserById(userId);
        res.status(200).json(user);
    } catch (error) {
        res.status(404).send(error.message);
    }
});

// Update User
router.put("/:id", async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const userData = req.body;
        const updatedUser = await userService.updateUserData(userId, userData);
        res.status(200).json(updatedUser);
    } catch (error) {
        res.status(400).send(error.message);
    }
});

// Delete User
router.delete("/:id", async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        await userService.deleteUserById(userId);
        res.status(204).send();
    } catch (error) {
        res.status(400).send(error.message);
    }
});

module.exports = router;
