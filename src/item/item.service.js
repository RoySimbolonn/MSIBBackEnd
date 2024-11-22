const itemRepository = require("./item.repository");

async function getAllItems() {
    return await itemRepository.findAllItems();
}

async function getItemById(id) {
    const item = await itemRepository.findItemById(id);
    if (!item) {
        throw new Error("Item not found");
    }
    return item;
}

async function createItem(itemData) {
    return await itemRepository.createItem(itemData);
}

async function updateItem(id, itemData) {
    const existingItem = await itemRepository.findItemById(id);
    if (!existingItem) {
        throw new Error("Item not found");
    }
    return await itemRepository.updateItem(id, itemData);
}

async function deleteItem(id) {
    const existingItem = await itemRepository.findItemById(id);
    if (!existingItem) {
        throw new Error("Item not found");
    }
    await itemRepository.deleteItem(id);
}

module.exports = {
    getAllItems,
    getItemById,
    createItem,
    updateItem,
    deleteItem
};