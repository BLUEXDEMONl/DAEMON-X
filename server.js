
const express = require('express');
const path = require('path');
const fsp = require('fs').promises; 
const fs = require('fs'); 
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const http = require('http');
const { Server } = require("socket.io");

const {
  // readJSONFile, // Not directly used by server.js anymore
  // writeJSONFile, // Not directly used by server.js anymore
  generateAlphanumericSlug, // Used by initDB (internally in functions.js) and /auth/register
  generateUniqueProfileSlug, // Used by initDB (internally in functions.js) and /auth/register
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
} = require('./functions.js');


const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

const DATABASE_DIR = path.join(__dirname, 'database'); // Still needed for initDirectories
const TEMP_UPLOADS_DIR = path.join(DATABASE_DIR, 'temp_uploads');


app.use(express.json({ limit: '30mb' })); 
app.use(express.urlencoded({ extended: true, limit: '30mb' })); 
app.use(express.static(path.join(__dirname, 'public')));


// Generic Multer storage for temporary uploads
const tempStorage = multer.diskStorage({
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

// Multer instance for avatar uploads (images only)
const avatarUpload = multer({ 
    storage: tempStorage,
    limits: { fileSize: 25 * 1024 * 1024 }, // 25MB limit
    fileFilter: function (req, file, cb) {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only image files are allowed for avatars!'), false);
        }
        cb(null, true);
    }
});

// Multer instance for post uploads (images/videos)
const postUpload = multer({ 
    storage: tempStorage,
    limits: { fileSize: 25 * 1024 * 1024 }, // 25MB limit
    fileFilter: function (req, file, cb) {
        if (!file.mimetype.startsWith('image/') && !file.mimetype.startsWith('video/')) {
            return cb(new Error('Only image or video files are allowed for posts!'), false);
        }
        cb(null, true);
    }
});

// Multer instance for chat file uploads (various types)
const chatFileUpload = multer({
    storage: tempStorage,
    limits: { fileSize: 25 * 1024 * 1024 }, // 25MB limit
    fileFilter: function (req, file, cb) {
        // Allow any file type for now, can be restricted if needed
        cb(null, true);
    }
});

async function initDirectories() {
  const DIRS_TO_CREATE = [
    { path: DATABASE_DIR, critical: true, name: "Database directory" },
    { path: TEMP_UPLOADS_DIR, critical: true, name: "Temporary uploads directory for multer" }
  ];

  for (const dirInfo of DIRS_TO_CREATE) {
    try {
      await fsp.mkdir(dirInfo.path, { recursive: true });
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

app.get(['/', '/login'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/space', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'space.html'));
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
    res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
});

app.post('/auth/user/avatar', avatarUpload.single('avatarFile'), async (req, res) => {
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
        console.error('Avatar update error with Catbox:', err.message);
        if (fs.existsSync(filePath)) {
            await fsp.unlink(filePath).catch(e => console.error("Error deleting temp file after server error:", e));
        }
        res.status(500).json({ success: false, message: `Server error during avatar update: ${err.message}` });
    }
});


app.get('/auth/verify-user/:identifier', async (req, res) => {
  const { identifier } = req.params;
  let userToReturn = null;

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
      userToReturn = { 
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        avatarUrl: user.avatarUrl || null,
        verified: user.verified || false,
        profileSlug: user.profileSlug
      };
      if (user.role === 'developer') {
        userToReturn.programmingType = user.programmingType;
        userToReturn.programmingLanguages = user.programmingLanguages;
      } else if (user.role === 'advertiser') {
        userToReturn.advertisingExperience = user.advertisingExperience;
        userToReturn.promotionIdeas = user.promotionIdeas;
      }
      res.json({ 
        success: true, 
        isValid: true,
        user: userToReturn
      });
    } else {
      res.status(404).json({ success: false, isValid: false, message: 'User not found.' });
    }
  } catch (err) {
    console.error('Verify user error:', err);
    res.status(500).json({ success: false, isValid: false, message: 'Server error during user verification.' });
  }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await getUsers();
        const usersForAdmin = users.map(u => {
            const userDto = { 
                id: u.id,
                username: u.username,
                email: u.email,
                role: u.role,
                avatarUrl: u.avatarUrl,
                verified: u.verified,
                profileSlug: u.profileSlug
            };
            if (u.role === 'developer') {
                userDto.programmingType = u.programmingType;
                userDto.programmingLanguages = u.programmingLanguages;
            } else if (u.role === 'advertiser') {
                userDto.advertisingExperience = u.advertisingExperience;
                userDto.promotionIdeas = u.promotionIdeas;
            }
            return userDto;
        });
        res.json(usersForAdmin);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to fetch users.' });
    }
});

app.patch('/api/admin/users/:userId/update', async (req, res) => {
    const { userId } = req.params;
    const { verified, role } = req.body;
    let updateApplied = false;

    if (typeof verified === 'undefined' && typeof role === 'undefined') {
        return res.status(400).json({ success: false, message: 'No update data provided. "verified" (boolean) or "role" (string) is required.' });
    }
    if (role && !['admin', 'developer', 'advertiser'].includes(role)) {
        return res.status(400).json({ success: false, message: 'Invalid role specified.' });
    }

    try {
        const users = await getUsers();
        const userIndex = users.findIndex(u => u.id === userId);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const targetUser = users[userIndex];

        if (typeof verified === 'boolean') {
            if (targetUser.username === 'admin' && verified === false) {
                return res.status(403).json({ success: false, message: "The primary admin user cannot be un-verified." });
            }
            targetUser.verified = verified;
            updateApplied = true;
        }

        if (role) {
            if (targetUser.username === 'admin' && role !== 'admin') {
                 return res.status(403).json({ success: false, message: "The primary admin user's role cannot be changed." });
            }
            targetUser.role = role;
            updateApplied = true;
        }
        
        if (updateApplied) {
            await saveUsers(users);
            res.json({ success: true, message: 'User updated successfully.', user: users[userIndex] });
        } else {
            res.json({ success: false, message: 'No changes applied.', user: users[userIndex] });
        }

    } catch (error) {
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
        res.status(500).json({ success: false, message: 'Server error deleting user.' });
    }
});

app.post('/api/admin/posts', postUpload.single('postImageFile'), async (req, res) => {
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
            mediaUrl: mediaUrl, 
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
        res.status(500).json({ success: false, message: 'Failed to fetch posts.' });
    }
});

app.delete('/api/admin/posts/:postId', async (req, res) => {
    const { postId } = req.params;
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
                             const otherUser = users.find(u => u.id === otherUserId);
                            userChatRooms[msg.roomId] = {
                                otherUserId: otherUserId,
                                otherUserUsername: otherUser ? otherUser.username : 'Unknown User',
                                otherUserAvatarUrl: otherUser ? otherUser.avatarUrl : null,
                                otherUserVerified: otherUser ? otherUser.verified || false : false,
                                lastMessage: msg,
                                unreadCount: 0 
                            };
                        }
                        if(msg.senderId !== userId && (!msg.readBy || !msg.readBy.includes(userId))) {
                           if(userChatRooms[msg.roomId]) userChatRooms[msg.roomId].unreadCount = (userChatRooms[msg.roomId].unreadCount || 0) +1;
                        }
                    }
                }
            }
        });

        const inboxSessions = Object.values(userChatRooms)
            .map(room => {
                return {
                    otherUser: {
                        id: room.otherUserId,
                        username: room.otherUserUsername,
                        avatarUrl: room.otherUserAvatarUrl,
                        verified: room.otherUserVerified
                    },
                    lastMessage: room.lastMessage || { text: 'No messages yet', timestamp: new Date(0).toISOString(), senderId: null },
                    roomId: room.lastMessage ? room.lastMessage.roomId : `${[userId, room.otherUserId].sort().join('_')}`,
                    unreadCount: room.unreadCount || 0
                };
            })
            .filter(session => session.otherUser.id) 
            .sort((a, b) => new Date(b.lastMessage.timestamp) - new Date(a.lastMessage.timestamp));

        res.json({ success: true, sessions: inboxSessions });

    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error fetching inbox sessions.' });
    }
});

app.post('/api/admin/broadcast', async (req, res) => {
    const { message } = req.body;
    const adminId = req.body.adminId; 

    if (!message || message.trim() === '') {
        return res.status(400).json({ success: false, message: 'Broadcast message cannot be empty.' });
    }

    if (adminId) {
        const users = await getUsers();
        const adminUser = users.find(u => u.id === adminId && u.role === 'admin');
        if (!adminUser) {
            return res.status(403).json({ success: false, message: 'Unauthorized: Only admins can send broadcasts.' });
        }
    } else {
         return res.status(400).json({ success: false, message: 'Admin ID is required for broadcasting.' });
    }


    try {
        const broadcasts = await getBroadcasts();
        const newBroadcast = {
            id: uuidv4(),
            message: message.trim(),
            timestamp: new Date().toISOString(),
            sender: 'admin' 
        };
        broadcasts.push(newBroadcast);
        await saveBroadcasts(broadcasts);

        io.emit('new broadcast', newBroadcast);

        res.status(201).json({ success: true, message: 'Broadcast sent successfully.', broadcast: newBroadcast });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error sending broadcast.' });
    }
});

app.get('/api/broadcasts', async (req, res) => {
    try {
        const broadcasts = await getBroadcasts();
        const sortedBroadcasts = broadcasts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        res.json({ success: true, broadcasts: sortedBroadcasts });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to fetch broadcasts.' });
    }
});

app.post('/api/chat/upload-file', chatFileUpload.single('chatFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }
    const filePath = req.file.path;
    try {
        const fileUrl = await uploadToCatbox(filePath);
        res.json({
            success: true,
            fileUrl: fileUrl,
            fileName: req.file.originalname,
            fileType: req.file.mimetype
        });
    } catch (error) {
        console.error('Chat file upload error:', error);
        if (fs.existsSync(filePath)) {
            await fsp.unlink(filePath).catch(e => console.error("Error deleting temp chat file after error:", e));
        }
        res.status(500).json({ success: false, message: 'Server error uploading chat file.' });
    }
});


io.on('connection', (socket) => {
    socket.on('join room', (roomId) => {
        socket.join(roomId);
    });

    socket.on('request history', async (roomId) => {
        try {
            const chatMessages = await getChatMessages();
            const history = chatMessages.filter(msg => msg.roomId === roomId).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            socket.emit('message history', history); 
        } catch (error) {
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
            // Handle error
        }
    });
    
    socket.on('messages read', async ({ roomId, userId }) => {
        try {
            let chatMessages = await getChatMessages();
            let updated = false;
            chatMessages.forEach(msg => {
                if (msg.roomId === roomId && msg.senderId !== userId) {
                    if (!msg.readBy) {
                        msg.readBy = [];
                    }
                    if (!msg.readBy.includes(userId)) {
                        msg.readBy.push(userId);
                        updated = true;
                    }
                }
            });
            if (updated) {
                await saveChatMessages(chatMessages);
            }
        } catch (error) {
            console.error('Error marking messages as read:', error);
        }
    });


    socket.on('disconnect', () => {
    });
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

server.listen(PORT, async () => {
  try {
    await initDirectories(); // Initialize server directories first
    await initDB(); // Then initialize DB (which might depend on DATABASE_DIR)
    console.log(`Server running on http://localhost:${PORT}`);
  } catch (error) {
    console.error("CRITICAL: Failed to initialize the application properly.", error);
    process.exit(1);
  }
});
