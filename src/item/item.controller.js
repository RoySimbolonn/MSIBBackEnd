const express = require("express");
const itemService = require("./item.service");
const authorizeJWT = require("../middleware/authorizeJWT");
const authorizeAdmin = require("../middleware/adminAuthorization");

const router = express.Router();

// Get All Items
router.get("/", authorizeJWT, async (req, res) => {
    try {
        const items = await itemService.getAllItems();
        res.status(200).json(items);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Get Item by ID
router.get("/:id",authorizeJWT, async (req, res) => {
    try {
        const item = await itemService.getItemById(parseInt(req.params.id));
        if (!item) {
            return res.status(404).json({ message: "Item not found" });
        }
        res.status(200).json(item);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Create New Item
router.post("/", authorizeAdmin, async (req, res) => {
    try {
        const newItem = await itemService.createItem(req.body);
        res.status(201).json(newItem);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Update Item
router.put("/:id", authorizeAdmin, async (req, res) => {
    try {
        const updatedItem = await itemService.updateItem(parseInt(req.params.id), req.body);
        res.status(200).json(updatedItem);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Delete Item
router.delete("/:id",authorizeAdmin,  async (req, res) => {
    try {
        await itemService.deleteItem(parseInt(req.params.id));
        res.status(204).send();
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

module.exports = router;