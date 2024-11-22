const prisma = require("../db");

async function findAllItems() {
    return await prisma.item.findMany();
}

async function findItemById(id) {
    return await prisma.item.findUnique({
        where: { id: id }
    });
}

async function createItem(itemData) {
    return await prisma.item.create({
        data: itemData
    });
}

async function updateItem(id, itemData) {
    return await prisma.item.update({
        where: { id: id },
        data: itemData
    });
}

async function deleteItem(id) {
    await prisma.item.delete({
        where: { id: id }
    });
}

module.exports = {
    findAllItems,
    findItemById,
    createItem,
    updateItem,
    deleteItem
};