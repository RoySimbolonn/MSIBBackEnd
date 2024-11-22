const prisma = require("../db");

async function createTransaction(userId, itemId, quantityBorrowed) {
  try {
    const newTransaction = await prisma.transaction.create({
      data: {
        userId,
        itemId,
        quantityBorrowed,
        status: "PENDING",
      },
      include: {
        user: true,
        item: true,
      },
    });
    return newTransaction;
  } catch (error) {
    throw new Error('Failed to create transaction');
  }
}

async function findAllTransactions() {
  try {
    const transactions = await prisma.transaction.findMany({
      include: {
        user: true,
        item: true,
      },
    });
    return transactions;
  } catch (error) {
    throw new Error('Failed to fetch transactions');
  }
}

async function findTransactionById(id) {
  try {
    const transaction = await prisma.transaction.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: true,
        item: true,
      },
    });
    return transaction;
  } catch (error) {
    throw new Error('Failed to fetch transaction');
  }
}

async function updateTransactionStatus(id, status) {
  try {
    const updatedTransaction = await prisma.transaction.update({
      where: { id: parseInt(id) },
      data: { status },
      include: {
        user: true,
        item: true,
      },
    });
    return updatedTransaction;
  } catch (error) {
    throw new Error('Failed to update transaction status');
  }
}

module.exports = {
  createTransaction,
  findAllTransactions,
  findTransactionById,
  updateTransactionStatus,
};