
const fsp = require('fs').promises;
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const FormData = require('form-data');

const DATABASE_DIR = path.join(__dirname, 'database');
const USERS_DB_FILE = path.join(DATABASE_DIR, 'db.json');
const CHATS_DB_FILE = path.join(DATABASE_DIR, 'chats.json');
const POSTS_DB_FILE = path.join(DATABASE_DIR, 'posts.json');
const BROADCAST_DB_FILE = path.join(DATABASE_DIR, 'broadcasts.json');

async function readJSONFile(filePath, defaultData = {}) {
  try {
    await fsp.access(filePath); 
    const data = await fsp.readFile(filePath, 'utf8');
    if (!data.trim()) { 
        await fsp.writeFile(filePath, JSON.stringify(defaultData, null, 2));
        return defaultData;
    }
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') { 
        try {
            await fsp.writeFile(filePath, JSON.stringify(defaultData, null, 2));
            return defaultData; 
        } catch (writeError) {
            console.error(`Failed to write default data to new file ${filePath}:`, writeError);
            throw writeError; 
        }
    } else if (error instanceof SyntaxError) { 
        console.error(`SyntaxError in ${filePath}. Initializing with default data. Error: ${error.message}`);
        try {
            await fsp.writeFile(filePath, JSON.stringify(defaultData, null, 2)); 
            return defaultData;
        } catch (writeError) {
            console.error(`Failed to write default data to corrupted file ${filePath}:`, writeError);
            throw writeError; 
        }
    } else if (error.code === 'EACCES') { 
        console.error(`Permission denied for ${filePath}. Cannot read/write. Error: ${error.message}`);
        throw error; 
    }
    console.error(`Unexpected error reading ${filePath}:`, error);
    throw error;
  }
}

async function writeJSONFile(filePath, data) {
  await fsp.writeFile(filePath, JSON.stringify(data, null, 2));
}

function generateAlphanumericSlug(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

async function generateUniqueProfileSlug(existingUsersList) {
  let slug;
  const existingSlugs = new Set(existingUsersList.map(u => u.profileSlug).filter(Boolean));
  do {
    slug = generateAlphanumericSlug(6);
  } while (existingSlugs.has(slug));
  return slug;
}

async function initDB() {
  // initDirectories() is called from server.js before this
  
  let usersDB = await readJSONFile(USERS_DB_FILE, { users: [] });
  if (!usersDB.users || !Array.isArray(usersDB.users)) {
    usersDB.users = [];
  }

  let dbNeedsUpdate = false;
  const existingSlugs = new Set(usersDB.users.map(u => u.profileSlug).filter(Boolean));

  for (const user of usersDB.users) {
    if (!user.profileSlug) {
      let newSlug;
      do {
        newSlug = generateAlphanumericSlug(6);
      } while (existingSlugs.has(newSlug));
      user.profileSlug = newSlug;
      existingSlugs.add(newSlug);
      dbNeedsUpdate = true;
    }
  }
  
  const adminUserExists = usersDB.users.some(u => u.username === 'admin' && u.role === 'admin');
  if (!adminUserExists) {
    const saltRounds = 10;
    const adminPasswordHash = await bcrypt.hash('Qwerty123', saltRounds);
    let adminProfileSlug;
     do {
        adminProfileSlug = generateAlphanumericSlug(6);
    } while (existingSlugs.has(adminProfileSlug));
    
    const adminUser = {
      id: uuidv4(),
      username: 'admin',
      email: 'admin@sophia.tech',
      passwordHash: adminPasswordHash,
      role: 'admin',
      avatarUrl: null,
      verified: true,
      profileSlug: adminProfileSlug
    };
    usersDB.users.push(adminUser);
    existingSlugs.add(adminProfileSlug);
    dbNeedsUpdate = true;
  }

  if (dbNeedsUpdate) {
    await writeJSONFile(USERS_DB_FILE, usersDB);
  }

  await readJSONFile(CHATS_DB_FILE, { chatMessages: [] });
  await readJSONFile(POSTS_DB_FILE, { posts: [] });
  await readJSONFile(BROADCAST_DB_FILE, { broadcasts: [] });
}

async function getUsers() {
  const db = await readJSONFile(USERS_DB_FILE, { users: [] });
  return db.users || [];
}

async function saveUsers(usersArray) {
  await writeJSONFile(USERS_DB_FILE, { users: usersArray });
}

async function getChatMessages() {
  const db = await readJSONFile(CHATS_DB_FILE, { chatMessages: [] });
  return db.chatMessages || [];
}

async function saveChatMessages(chatMessagesArray) {
  await writeJSONFile(CHATS_DB_FILE, { chatMessages: chatMessagesArray });
}

async function getPosts() {
  const db = await readJSONFile(POSTS_DB_FILE, { posts: [] });
  return db.posts || [];
}

async function savePosts(postsArray) {
  await writeJSONFile(POSTS_DB_FILE, { posts: postsArray });
}
async function getBroadcasts() {
    const db = await readJSONFile(BROADCAST_DB_FILE, { broadcasts: [] });
    return db.broadcasts || [];
}

async function saveBroadcasts(broadcastsArray) {
    await writeJSONFile(BROADCAST_DB_FILE, { broadcasts: broadcastsArray });
}

async function uploadToCatbox(filePath) {
    const form = new FormData();
    form.append('reqtype', 'fileupload');
    form.append('fileToUpload', fs.createReadStream(filePath));

    const catboxResponse = await axios.post('https://catbox.moe/user/api.php', form, {
        headers: form.getHeaders()
    });

    try {
        await fsp.unlink(filePath);
    } catch (unlinkError) {
        console.error('Error deleting temp file after Catbox upload:', unlinkError);
    }

    if (!catboxResponse.data || typeof catboxResponse.data !== 'string' || !catboxResponse.data.startsWith('http')) {
        console.error('Catbox API error response:', catboxResponse.data);
        throw new Error('Failed to upload to Catbox.');
    }
    return catboxResponse.data;
}

module.exports = {
  readJSONFile,
  writeJSONFile,
  generateAlphanumericSlug,
  generateUniqueProfileSlug,
  initDB,
  getUsers,
  saveUsers,
  getChatMessages,
  saveChatMessages,
  getPosts,
  savePosts,
  getBroadcasts,
  saveBroadcasts,
  uploadToCatbox
};
