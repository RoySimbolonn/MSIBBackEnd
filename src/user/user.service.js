const bcrypt = require("bcrypt");
const {
  insertUser,
  findAllUsers,
  findUserById,
  updateUser,  // Pastikan fungsi ini ada
  deleteUser,
} = require("./user.repository");

// Create a new user
async function createUser(newUserData) {
  // Hash password before saving
  const hashedPassword = await bcrypt.hash(newUserData.password, 10);
  newUserData.password = hashedPassword;
  const newUser = await insertUser(newUserData);
  return newUser;
}

// Get all users
async function getAllUsers() {
  const users = await findAllUsers();
  return users;
}

// Get user by ID
async function getUserById(id) {
  const user = await findUserById(id);
  if (!user) {
    throw new Error("User not found");
  }
  return user;
}

// Update user data
async function updateUserData(id, userData) {  // Pastikan Anda memanggil ini di controller
  // Only hash the password if it is being updated
  if (userData.password) {
    userData.password = await bcrypt.hash(userData.password, 10);
  }

  const updatedUser = await updateUser(id, userData);
  if (!updatedUser) {
    throw new Error("User not found");
  }
  return updatedUser;
}

// Delete user by ID
async function deleteUserById(id) {
  const user = await findUserById(id);
  if (!user) {
    throw new Error("User not found");
  }
  await deleteUser(id);
}

module.exports = {
  createUser,
  getAllUsers,
  getUserById,
  updateUserData,  // Pastikan ini diekspor
  deleteUserById,
};
