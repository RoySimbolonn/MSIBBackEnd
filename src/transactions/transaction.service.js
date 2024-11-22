const transactionRepository = require("./transaction.repository");
const itemRepository = require("../item/item.repository");

async function borrowItem(userId, itemId, quantityBorrowed) {
  const item = await itemRepository.findItemById(itemId);
  if (!item) {
    throw new Error('Item not found');
  }
  if (item.quantity < quantityBorrowed) {
    throw new Error('Not enough items available');
  }
  
  const newTransaction = await transactionRepository.createTransaction(userId, itemId, quantityBorrowed);
  
  await itemRepository.updateItem(itemId, { quantity: item.quantity - quantityBorrowed });
  
  return newTransaction;
}

async function getAllTransactions() {
  return await transactionRepository.findAllTransactions();
}

async function getTransactionById(id) {
  const transaction = await transactionRepository.findTransactionById(id);
  if (!transaction) {
    throw new Error('Transaction not found');
  }
  return transaction;
}

async function updateTransactionStatus(id, status) {
  const transaction = await transactionRepository.findTransactionById(id);
  if (!transaction) {
    throw new Error('Transaction not found');
  }
  return await transactionRepository.updateTransactionStatus(id, status);
}

async function returnItem(id) {
  const transaction = await transactionRepository.findTransactionById(id);
  if (!transaction) {
    throw new Error('Transaction not found');
  }
  if (transaction.status === 'RETURNED') {
    throw new Error('Item already returned');
  }
  
  const item = await itemRepository.findItemById(transaction.itemId);
  await itemRepository.updateItem(transaction.itemId, { quantity: item.quantity + transaction.quantityBorrowed });
  
  return await transactionRepository.updateTransactionStatus(id, 'RETURNED');
}

module.exports = {
  borrowItem,
  getAllTransactions,
  getTransactionById,
  updateTransactionStatus,
  returnItem,
};