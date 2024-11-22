const express = require('express');
const router = express.Router();
const authController = require('./auth.controller');
const itemController = require('./item.controller');
const transactionController = require('./transactions.controller');
const userController = require('./user.controller');
const authorizeJWT = require('./authorizeJWT');
const authorizeAdmin = require('./authorizeAdmin');

// Auth routes
router.use('/auth', authController);

// Item routes
router.get('/items', authorizeJWT, itemController.getAllItems);
router.get('/items/:id', authorizeJWT, itemController.getItemById);
router.post('/items', authorizeAdmin, itemController.createItem);
router.put('/items/:id', authorizeAdmin, itemController.updateItem);
router.delete('/items/:id', authorizeAdmin, itemController.deleteItem);

// Transaction routes
router.post('/transactions/borrow', authorizeJWT, transactionController.borrowItem);
router.get('/transactions', authorizeAdmin, transactionController.getAllTransactions);
router.get('/transactions/:id', authorizeJWT, transactionController.getTransactionById);
router.put('/transactions/:id/status', authorizeAdmin, transactionController.updateTransactionStatus);
router.post('/transactions/:id/return', authorizeJWT, transactionController.returnItem);

// User routes
router.get('/users', authorizeAdmin, userController.getAllUsers);
router.get('/users/:id', authorizeJWT, userController.getUserById);
router.post('/users', authorizeAdmin, userController.createUser);
router.put('/users/:id', authorizeAdmin, userController.updateUserData);
router.delete('/users/:id', authorizeAdmin, userController.deleteUserById);

module.exports = router;