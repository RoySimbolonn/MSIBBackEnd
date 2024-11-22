const prisma = require("../db"); // Pastikan Anda memiliki koneksi Prisma yang benar

async function insertUser(userData) {
  const newUser = await prisma.user.create({
    data: userData,
  });
  return newUser;
}

async function findAllUsers() {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      username: true,
      email: true,
      role: true,
      createdAt: true,
    },
  });
  return users;
} 

async function findUserById(id) {
  const user = await prisma.user.findUnique({
    where: { id: parseInt(id) },
    select: {
      id: true,
      username: true,
      email: true,
      role: true,
      createdAt: true,
    },
  });
  return user;
}

// Letakkan fungsi updateUser di sini
async function updateUser(id, userData) {
  const updatedUser = await prisma.user.update({
    where: { id: parseInt(id) },
    data: userData,
    select: {
      id: true,
      username: true,
      email: true,
      role: true,
      createdAt: true,
    },
  });
  return updatedUser;
}

async function deleteUser(id) {
  await prisma.user.delete({
    where: { id: parseInt(id) },
  });
}

module.exports = {
  insertUser,
  findAllUsers,
  findUserById,
  updateUser, // Pastikan ini diekspor
  deleteUser,
};
