
const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const multer = require('multer'); 

const {
  UPLOADS_DIR,
  ensureRequiredDirsExist,
  readDb,
  writeDb,
  uploadToCatbox,
} = require('./func'); 

const app = express();
const port = 7860;
const SALT_ROUNDS = 10;

app.use(express.json());

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR); 
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

app.get('/register.html', (req, res) => res.redirect(301, '/register'));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/login.html', (req, res) => res.redirect(301, '/login'));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/home', (req, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/space', (req, res) => res.sendFile(path.join(__dirname, 'public', 'space.html')));


app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.redirect('/login'));

app.post('/auth/upload-profile-picture', upload.single('profilePicture'), async (req, res) => {
    const { userId } = req.body;

    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }
    if (!userId) {
        try { 
          const fsp = require('fs/promises'); 
          await fsp.unlink(req.file.path); 
        } catch (e) { console.error("Error deleting orphaned file", e); }
        return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    try {
        const profilePictureUrl = await uploadToCatbox(req.file.path);
        
        const users = readDb();
        const userIndex = users.findIndex(u => u.id === userId);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        users[userIndex].profilePictureUrl = profilePictureUrl;
        writeDb(users);

        res.json({ success: true, message: 'Profile picture uploaded successfully!', profilePictureUrl });

    } catch (error) {
        console.error('Error processing profile picture upload:', error);
        res.status(500).json({ success: false, message: error.message || 'Failed to upload profile picture.' });
    }
});


app.post('/auth/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'Username, email, and password are required.' });
  }
   if (username.includes(' ')) {
    return res.status(400).json({ success: false, message: 'Username cannot contain spaces.' });
  }
  if (password.length < 8) {
     return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format.' });
  }

  const users = readDb();

  if (users.some(user => user.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ success: false, message: 'Username already exists.' });
  }
  if (users.some(user => user.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ success: false, message: 'Email already registered.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const newUser = {
      id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      profilePictureUrl: '' 
    };

    users.push(newUser);
    writeDb(users);
    res.status(201).json({ success: true, message: 'Registration successful! You will be redirected to login.' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ success: false, message: 'An error occurred during registration. Please try again.' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { username, password: inputPassword } = req.body;

  if (!username || !inputPassword) {
    return res.status(400).json({ success: false, message: 'Username/email and password are required.' });
  }

  const users = readDb();
  const user = users.find(u => 
    u.username.toLowerCase() === username.toLowerCase() || 
    u.email.toLowerCase() === username.toLowerCase()
  );

  if (!user) {
    return res.status(401).json({ success: false, message: 'Account not found. Please check your username or email.' });
  }

  try {
    const isMatch = await bcrypt.compare(inputPassword, user.password);
    if (isMatch) {
      const { password, ...userData } = user; 
      res.status(200).json({ 
        success: true, 
        message: 'Login successful! Redirecting...', 
        user: userData, 
        redirectTo: '/home' 
      });
    } else {
      return res.status(401).json({ success: false, message: 'Incorrect password. Please try again.' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, message: 'An error occurred during login. Please try again.' });
  }
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  ensureRequiredDirsExist(); 
});
