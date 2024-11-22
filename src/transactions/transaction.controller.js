const express = require("express");
const router = express.Router();
const transactionService = require("./transaction.service");

const authorizeJWT = require("../middleware/authorizeJWT");

const adminAuthorization = require("../middleware/adminAuthorization");



// Borrow Item
router.post("/borrow", authorizeJWT,async (req, res) => {
    try {
        const { userId, itemId, quantityBorrowed } = req.body;
        const newTransaction = await transactionService.borrowItem(userId, itemId, quantityBorrowed);
        res.status(201).json(newTransaction);
    } catch (error) {
        res.status(400).send(error.message);
    }
});

// Get All Transactions
router.get("/",adminAuthorization, async (req, res) => {
    try {
        const transactions = await transactionService.getAllTransactions();
        res.status(200).json(transactions);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Get Transaction by ID
router.get("/:id",authorizeJWT, async (req, res) => {
    try {
        const transactionId = parseInt(req.params.id);
        const transaction = await transactionService.getTransactionById(transactionId);
        res.status(200).json(transaction);
    } catch (error) {
        res.status(404).send(error.message);
    }
});

// Update Transaction Status
router.put("/:id/status", adminAuthorization, async (req, res) => {
    try {
        const transactionId = parseInt(req.params.id);
        const { status } = req.body;
        const updatedTransaction = await transactionService.updateTransactionStatus(transactionId, status);
        res.status(200).json(updatedTransaction);
    } catch (error) {
        res.status(400).send(error.message);
    }
});

// Return Item
router.post("/:id/return",authorizeJWT, async (req, res) => {
    try {
        const transactionId = parseInt(req.params.id);
        const returnedTransaction = await transactionService.returnItem(transactionId);
        res.status(200).json(returnedTransaction);
    } catch (error) {
        res.status(400).send(error.message);
    }
});

module.exports = router;