const express = require('express');
const path = require('path');
const fsp = require('fs').promises; 
const fs = require('fs'); 
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 7860;

const DATABASE_DIR = path.join(__dirname, 'database');
const USERS_DB_FILE = path.join(DATABASE_DIR, 'db.json');
const CHATS_DB_FILE = path.join(DATABASE_DIR, 'chats.json');
const POSTS_DB_FILE = path.join(DATABASE_DIR, 'posts.json');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
const TEMP_UPLOADS_DIR = path.join(__dirname, 'temp_uploads');


app.use(express.json({ limit: '30mb' })); 
app.use(express.urlencoded({ extended: true, limit: '30mb' })); 
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));


const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (!fs.existsSync(TEMP_UPLOADS_DIR)){
            fs.mkdirSync(TEMP_UPLOADS_DIR, { recursive: true });
        }
        cb(null, TEMP_UPLOADS_DIR); 
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 25 * 1024 * 1024 }, // 25MB limit
    fileFilter: function (req, file, cb) {
        if (!file.mimetype.startsWith('image/') && !file.mimetype.startsWith('video/')) {
            return cb(new Error('Only image or video files are allowed!'), false);
        }
        cb(null, true);
    }
});

async function readJSONFile(filePath, defaultData = {}) {
  try {
    await fsp.access(filePath); 
    const data = await fsp.readFile(filePath, 'utf8');
    if (!data.trim()) { 
        console.warn(`${filePath} is empty. Initializing with default data.`);
        await fsp.writeFile(filePath, JSON.stringify(defaultData, null, 2));
        return defaultData;
    }
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') { 
        console.warn(`${filePath} not found. Creating with default data.`);
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

async function initDirectories() {
  const DIRS_TO_CREATE = [
    { path: DATABASE_DIR, critical: true, name: "Database directory" },
    { path: UPLOADS_DIR, critical: true, name: "Public uploads directory" }, 
    { path: TEMP_UPLOADS_DIR, critical: true, name: "Temporary uploads directory for multer" }
  ];

  for (const dirInfo of DIRS_TO_CREATE) {
    try {
      await fsp.mkdir(dirInfo.path, { recursive: true });
      console.log(`${dirInfo.name} (${dirInfo.path}) ensured.`);
    } catch (error) {
      if (error.code !== 'EEXIST') {
        console.error(`Failed to create ${dirInfo.name} (${dirInfo.path}):`, error);
        if (dirInfo.critical) {
          throw new Error(`Failed to create critical directory ${dirInfo.name} at ${dirInfo.path}. Server cannot start.`);
        }
      }
    }
  }
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
  await initDirectories();
  
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
    console.log(`Default admin user created in ${USERS_DB_FILE}.`);
  }

  if (dbNeedsUpdate) {
    await writeJSONFile(USERS_DB_FILE, usersDB);
    console.log(`${USERS_DB_FILE} updated with profile slugs and/or default admin.`);
  }

  let chatsDB = await readJSONFile(CHATS_DB_FILE, { chatMessages: [] });
  if (!chatsDB.chatMessages || !Array.isArray(chatsDB.chatMessages)) {
    chatsDB.chatMessages = [];
    await writeJSONFile(CHATS_DB_FILE, chatsDB);
  }
  await readJSONFile(POSTS_DB_FILE, { posts: [] });

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
        throw new Error('Failed to upload image to Catbox.');
    }
    return catboxResponse.data;
}


app.get(['/', '/login'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/panel', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'panel.html'));
});

app.get('/get-all-users', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'get-all-users.html'));
});

app.get('/post-update.html', (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'post-update.html'));
});

app.get('/inbox', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'inbox.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/profile/:identifier', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'view-profile.html'));
});

app.get('/chat/:userId?', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username/email and password are required.' });
  }

  try {
    const users = await getUsers();
    const user = users.find(u => (u.username.toLowerCase() === username.toLowerCase() || u.email.toLowerCase() === username.toLowerCase()));

    if (user && await bcrypt.compare(password, user.passwordHash)) {
      res.json({
        success: true,
        message: 'Login successful.',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          avatarUrl: user.avatarUrl || null,
          verified: user.verified || false,
          profileSlug: user.profileSlug 
        },
        redirectTo: user.role === 'admin' ? '/panel' : '/dashboard'
      });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error during login.' });
  }
});

app.post('/auth/register', async (req, res) => {
  let { 
    username, email, password, role, 
    programmingType, programmingLanguages, 
    advertisingExperience, promotionIdeas 
  } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'Username, email, and password are required.' });
  }

  username = username.trim();
  email = email.trim().toLowerCase();
  
  if (username.toLowerCase() === 'admin') {
      role = 'admin'; 
  } else if (!role || !['developer', 'advertiser'].includes(role)) {
    return res.status(400).json({ success: false, message: 'A valid role (Developer or Advertiser) is required.' });
  }

  if (!/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email format.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
  }

  if (role === 'developer') {
    if (!programmingType) {
      return res.status(400).json({ success: false, message: 'Programming type is required for developers.' });
    }
    if (!programmingLanguages || !Array.isArray(programmingLanguages) || programmingLanguages.length === 0) {
      return res.status(400).json({ success: false, message: 'At least one programming language is required for developers.' });
    }
  } else if (role === 'advertiser') {
    if (!advertisingExperience) {
      return res.status(400).json({ success: false, message: 'Advertising experience is required for advertisers.' });
    }
    if (!promotionIdeas || promotionIdeas.trim() === '') {
      return res.status(400).json({ success: false, message: 'Promotion ideas are required for advertisers.' });
    }
  }

  try {
    const users = await getUsers();

    if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ success: false, message: 'Username already exists.' });
    }
    if (users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const profileSlug = await generateUniqueProfileSlug(users);

    const newUser = {
      id: uuidv4(),
      username,
      email,
      passwordHash,
      role,
      avatarUrl: null,
      verified: username.toLowerCase() === 'admin', 
      profileSlug
    };

    if (role === 'developer') {
      newUser.programmingType = programmingType;
      newUser.programmingLanguages = programmingLanguages;
    } else if (role === 'advertiser') {
      newUser.advertisingExperience = advertisingExperience;
      newUser.promotionIdeas = promotionIdeas.trim();
    }

    users.push(newUser);
    await saveUsers(users);
    res.status(201).json({ success: true, message: 'User registered successfully. Please login.' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
});

app.post('/auth/user/avatar', upload.single('avatarFile'), async (req, res) => {
    const { userId } = req.body;
    if (!userId) {
        if (req.file && req.file.path && fs.existsSync(req.file.path)) {
             await fsp.unlink(req.file.path).catch(e => console.error("Error deleting temp file for missing userId:", e));
        }
        return res.status(400).json({ success: false, message: 'User ID is required.' });
    }
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Avatar file is required.' });
    }
    
    const filePath = req.file.path;
    
    try {
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.id === userId);

        if (userIndex === -1) {
            if (fs.existsSync(filePath)) await fsp.unlink(filePath).catch(e => console.error("Error deleting temp file for not found user:", e));
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        const catboxFileUrl = await uploadToCatbox(filePath); 
        
        users[userIndex].avatarUrl = catboxFileUrl;
        await saveUsers(users);

        res.json({
            success: true,
            message: 'Avatar updated successfully.',
            avatarUrl: catboxFileUrl
        });

    } catch (err) {
        console.error('Avatar update error:', err.message);
        if (fs.existsSync(filePath)) {
            await fsp.unlink(filePath).catch(e => console.error("Error deleting temp file after server error:", e));
        }
        res.status(500).json({ success: false, message: `Server error during avatar update: ${err.message}` });
    }
});


app.get('/auth/verify-user/:identifier', async (req, res) => {
  const { identifier } = req.params;
  if (!identifier) {
    return res.status(400).json({ success: false, message: 'User identifier is required.' });
  }

  try {
    const users = await getUsers();
    let user;

    if (identifier.length === 6 && /^[a-zA-Z0-9]+$/.test(identifier)) {
      user = users.find(u => u.profileSlug === identifier);
    } else { 
      user = users.find(u => u.id === identifier);
    }

    if (user) {
      res.json({ 
        success: true, 
        isValid: true,
        user: { 
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            avatarUrl: user.avatarUrl || null,
            verified: user.verified || false,
            profileSlug: user.profileSlug
        }
      });
    } else {
      res.status(404).json({ success: false, isValid: false, message: 'User not found in database.' });
    }
  } catch (err) {
    console.error('Verify user error:', err);
    res.status(500).json({ success: false, isValid: false, message: 'Server error during user verification.' });
  }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await getUsers();
        const usersForAdmin = users.map(u => ({
            id: u.id,
            username: u.username,
            email: u.email,
            role: u.role,
            avatarUrl: u.avatarUrl,
            verified: u.verified,
            profileSlug: u.profileSlug
        }));
        res.json(usersForAdmin);
    } catch (error) {
        console.error('Error fetching users for admin:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch users.' });
    }
});

app.patch('/api/admin/users/:userId/update', async (req, res) => {
    const { userId } = req.params;
    const { verified } = req.body; 

    if (typeof verified !== 'boolean') {
        return res.status(400).json({ success: false, message: 'Invalid update data. "verified" (boolean) is required.' });
    }

    try {
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.id === userId);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        if (users[userIndex].username === 'admin' && verified === false) {
            return res.status(403).json({ success: false, message: "The primary admin user cannot be un-verified." });
        }

        users[userIndex].verified = verified;
        await saveUsers(users);
        res.json({ success: true, message: 'User verification status updated.', user: users[userIndex] });
    } catch (error) {
        console.error('Error updating user verification status:', error);
        res.status(500).json({ success: false, message: 'Server error updating user.' });
    }
});

app.delete('/api/admin/users/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        let users = await getUsers();
        const userToDelete = users.find(u => u.id === userId);

        if (!userToDelete) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        if (userToDelete.username === 'admin') {
            return res.status(403).json({ success: false, message: "The primary admin user cannot be deleted." });
        }

        users = users.filter(u => u.id !== userId);
        await saveUsers(users);
        res.json({ success: true, message: 'User deleted successfully.' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ success: false, message: 'Server error deleting user.' });
    }
});

app.post('/api/admin/posts', upload.single('postImageFile'), async (req, res) => {
    const { caption, authorId, authorUsername } = req.body;
    const mediaFile = req.file; 

    if (!mediaFile) {
        return res.status(400).json({ success: false, message: 'Image or video file is required for a post.' });
    }
    if (!caption || caption.trim() === '') {
        if (fs.existsSync(mediaFile.path)) await fsp.unlink(mediaFile.path).catch(e => console.error("Error deleting temp post file for missing caption:", e));
        return res.status(400).json({ success: false, message: 'Caption is required.' });
    }
    if (!authorId || !authorUsername) {
        if (fs.existsSync(mediaFile.path)) await fsp.unlink(mediaFile.path).catch(e => console.error("Error deleting temp post file for missing author:", e));
        return res.status(400).json({ success: false, message: 'Author information is missing.' });
    }

    try {
        const mediaUrl = await uploadToCatbox(mediaFile.path); 
        
        const newPost = {
            id: uuidv4(),
            imageUrl: mediaUrl, 
            mimetype: mediaFile.mimetype, 
            caption,
            timestamp: new Date().toISOString(),
            authorId,
            authorUsername
        };

        const postsData = await getPosts();
        postsData.push(newPost);
        await savePosts(postsData);

        res.status(201).json({ success: true, message: 'Post created successfully.', post: newPost });

    } catch (error) {
        console.error('Error creating post:', error);
        if (mediaFile && mediaFile.path && fs.existsSync(mediaFile.path)) {
             await fsp.unlink(mediaFile.path).catch(e => console.error("Error cleaning up post file after error:", e));
        }
        res.status(500).json({ success: false, message: 'Server error creating post.' });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await getPosts();
        const sortedPosts = posts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        res.json(sortedPosts);
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch posts.' });
    }
});

app.delete('/api/admin/posts/:postId', async (req, res) => {
    const { postId } = req.params;
    // TODO: Add admin role verification middleware here if needed
    try {
        let posts = await getPosts();
        const initialLength = posts.length;
        posts = posts.filter(post => post.id !== postId);

        if (posts.length === initialLength) {
            return res.status(404).json({ success: false, message: 'Post not found.' });
        }

        await savePosts(posts);
        res.json({ success: true, message: 'Post deleted successfully.' });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ success: false, message: 'Server error deleting post.' });
    }
});


app.get('/api/inbox-sessions/:userId', async (req, res) => {
    const { userId } = req.params;
    if (!userId) {
        return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    try {
        const allMessages = await getChatMessages();
        const users = await getUsers();
        const userChatRooms = {}; 

        allMessages.forEach(msg => {
            if (msg.roomId) {
                const participants = msg.roomId.split('_');
                if (participants.includes(userId)) {
                    const otherUserId = participants.find(pId => pId !== userId);
                    if (otherUserId) {
                        if (!userChatRooms[msg.roomId] || new Date(msg.timestamp) > new Date(userChatRooms[msg.roomId].lastMessage.timestamp)) {
                            userChatRooms[msg.roomId] = {
                                otherUserId: otherUserId,
                                lastMessage: msg, 
                            };
                        }
                    }
                }
            }
        });

        const inboxSessions = Object.values(userChatRooms)
            .map(room => {
                const otherUser = users.find(u => u.id === room.otherUserId);
                return {
                    otherUser: {
                        id: otherUser ? otherUser.id : room.otherUserId,
                        username: otherUser ? otherUser.username : 'Unknown User',
                        avatarUrl: otherUser ? otherUser.avatarUrl : null,
                        verified: otherUser ? otherUser.verified || false : false 
                    },
                    lastMessage: room.lastMessage || { text: 'No messages yet', timestamp: new Date(0).toISOString(), senderId: null },
                    roomId: room.lastMessage ? room.lastMessage.roomId : `${[userId, room.otherUserId].sort().join('_')}`
                };
            })
            .filter(session => session.otherUser.id) 
            .sort((a, b) => new Date(b.lastMessage.timestamp) - new Date(a.lastMessage.timestamp));

        res.json({ success: true, sessions: inboxSessions });

    } catch (err) {
        console.error('Error fetching inbox sessions:', err);
        res.status(500).json({ success: false, message: 'Server error fetching inbox sessions.' });
    }
});


io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('join room', (roomId) => {
        socket.join(roomId);
        console.log(`User ${socket.id} joined room ${roomId}`);
    });

    socket.on('request history', async (roomId) => {
        try {
            const chatMessages = await getChatMessages();
            const history = chatMessages.filter(msg => msg.roomId === roomId).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            socket.emit('message history', history); 
        } catch (error) {
            console.error('Error fetching message history:', error);
            socket.emit('message history', []); 
        }
    });

    socket.on('chat message', async (msg) => { 
        try {
            const chatMessages = await getChatMessages();
            const newMessage = { ...msg, id: uuidv4() }; 
            chatMessages.push(newMessage);
            await saveChatMessages(chatMessages);
            io.to(msg.roomId).emit('chat message', newMessage); 
        } catch (error) {
            console.error('Error saving/broadcasting chat message:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

server.listen(PORT, async () => {
  try {
    await initDB();
    console.log(`Server running on http://localhost:${PORT}`);
  } catch (error) {
    console.error("CRITICAL: Failed to initialize the application properly.", error);
    process.exit(1);
  }
});

