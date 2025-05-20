
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const axios = require('axios');
const FormData = require('form-data');

const DB_DIR = path.join(__dirname, 'database');
const DB_PATH = path.join(DB_DIR, 'db.json');
const UPLOADS_DIR = path.join(DB_DIR, 'uploads'); // Changed to be inside DB_DIR

const ensureRequiredDirsExist = () => {
  if (!fs.existsSync(DB_DIR)) {
    fs.mkdirSync(DB_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify([]), 'utf8');
  }
  // This will now create PROJECT_ROOT/database/uploads
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
};

const readDb = () => {
  ensureRequiredDirsExist();
  try {
    const data = fs.readFileSync(DB_PATH, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading database:', error);
    fs.writeFileSync(DB_PATH, JSON.stringify([]), 'utf8');
    return [];
  }
};

const writeDb = (data) => {
  ensureRequiredDirsExist();
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  } catch (error) {
    console.error('Error writing to database:', error);
  }
};

async function uploadToCatbox(filePath) {
    const form = new FormData();
    form.append('reqtype', 'fileupload');
    form.append('fileToUpload', fs.createReadStream(filePath));

    let catboxResponse;
    try {
        catboxResponse = await axios.post('https://catbox.moe/user/api.php', form, {
            headers: form.getHeaders()
        });
    } catch (uploadError) {
        console.error('Catbox API request error:', uploadError.message);
        if (uploadError.response) {
            console.error('Catbox error response data:', uploadError.response.data);
            console.error('Catbox error response status:', uploadError.response.status);
        }
        try {
            await fsp.unlink(filePath); // Use fsp for promise-based unlink
        } catch (unlinkError) {
            console.error('Error deleting temp file after Catbox API request error:', unlinkError);
        }
        throw new Error('Failed to upload to Catbox due to API request error.');
    }

    try {
        await fsp.unlink(filePath); // Use fsp for promise-based unlink
    } catch (unlinkError) {
        console.error('Error deleting temp file after Catbox upload:', unlinkError);
    }

    if (!catboxResponse.data || typeof catboxResponse.data !== 'string' || !catboxResponse.data.startsWith('http')) {
        console.error('Catbox API unexpected response:', catboxResponse.data);
        throw new Error('Failed to upload to Catbox or received an invalid response.');
    }
    return catboxResponse.data;
}

module.exports = {
  DB_DIR,
  DB_PATH,
  UPLOADS_DIR,
  ensureRequiredDirsExist,
  readDb,
  writeDb,
  uploadToCatbox,
};
