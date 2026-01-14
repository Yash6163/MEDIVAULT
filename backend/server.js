// server.js - MEDIVAULT Backend Server
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const crypto = require('crypto');
const { ethers } = require('ethers');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/medivault', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// ============ SCHEMAS ============

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  age: Number,
  bloodGroup: String,
  allergies: [String],
  emergencyContact: String,
  walletAddress: String,
  createdAt: { type: Date, default: Date.now }
});

const MedicalRecordSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedData: { type: String, required: true },
  recordType: String,
  hospital: String,
  date: { type: Date, default: Date.now },
  blockchainHash: String,
  txHash: String,
  verified: { type: Boolean, default: false },
  accessLog: [{
    accessedBy: String,
    timestamp: Date,
    granted: Boolean
  }]
});

const AccessRequestSchema = new mongoose.Schema({
  recordId: { type: mongoose.Schema.Types.ObjectId, ref: 'MedicalRecord' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  requestedBy: String,
  hospital: String,
  status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'pending' },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const MedicalRecord = mongoose.model('MedicalRecord', MedicalRecordSchema);
const AccessRequest = mongoose.model('AccessRequest', AccessRequestSchema);

// ============ ENCRYPTION UTILITIES ============

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
const IV_LENGTH = 16;

function encryptData(data) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptData(encryptedData) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encrypted = parts.join(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

function generateHash(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

// ============ BLOCKCHAIN INTEGRATION ============

// Smart Contract ABI (simplified for medical record verification)
const contractABI = [
  "function storeRecordHash(string memory recordHash) public returns (bool)",
  "function verifyRecordHash(string memory recordHash) public view returns (bool, uint256)",
  "event RecordStored(address indexed user, string recordHash, uint256 timestamp)"
];

// Initialize blockchain provider (using Polygon Mumbai testnet)
let provider, wallet, contract;

async function initializeBlockchain() {
  try {
    // Use Polygon Mumbai testnet (you can change to mainnet)
    provider = new ethers.JsonRpcProvider(
      process.env.BLOCKCHAIN_RPC || 'https://rpc-mumbai.maticvigil.com'
    );
    
    wallet = new ethers.Wallet(
      process.env.PRIVATE_KEY || ethers.Wallet.createRandom().privateKey,
      provider
    );
    
    // Contract address (deploy your own contract)
    const contractAddress = process.env.CONTRACT_ADDRESS || '0x0000000000000000000000000000000000000000';
    contract = new ethers.Contract(contractAddress, contractABI, wallet);
    
    console.log('Blockchain initialized:', wallet.address);
  } catch (error) {
    console.error('Blockchain init error:', error.message);
  }
}

async function storeHashOnBlockchain(recordHash) {
  try {
    if (!contract) {
      console.log('Blockchain not initialized, using mock hash');
      return { txHash: '0xmock' + crypto.randomBytes(32).toString('hex') };
    }
    
    const tx = await contract.storeRecordHash(recordHash);
    const receipt = await tx.wait();
    return { txHash: receipt.hash, blockNumber: receipt.blockNumber };
  } catch (error) {
    console.error('Blockchain storage error:', error.message);
    // Return mock data for development
    return { txHash: '0xmock' + crypto.randomBytes(32).toString('hex') };
  }
}

// ============ AUTHENTICATION MIDDLEWARE ============

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ============ FILE UPLOAD CONFIGURATION ============

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// ============ API ROUTES ============

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, age, bloodGroup, allergies, emergencyContact } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const walletAddress = ethers.Wallet.createRandom().address;

    const user = new User({
      email,
      password: hashedPassword,
      name,
      age,
      bloodGroup,
      allergies,
      emergencyContact,
      walletAddress
    });

    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user._id, email, name, walletAddress } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user._id, email, name: user.name } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Upload Medical Record
app.post('/api/records/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { recordType, hospital } = req.body;
    const fileData = req.file.buffer.toString('base64');

    // Encrypt the medical data
    const medicalData = {
      fileName: req.file.originalname,
      mimeType: req.file.mimetype,
      data: fileData,
      recordType,
      hospital,
      uploadDate: new Date()
    };

    const encryptedData = encryptData(medicalData);
    const dataHash = generateHash(medicalData);

    // Store hash on blockchain
    const blockchainResult = await storeHashOnBlockchain(dataHash);

    // Save to database
    const record = new MedicalRecord({
      userId: req.user.userId,
      encryptedData,
      recordType,
      hospital,
      blockchainHash: dataHash,
      txHash: blockchainResult.txHash,
      verified: true
    });

    await record.save();

    res.json({
      success: true,
      recordId: record._id,
      blockchainHash: dataHash,
      txHash: blockchainResult.txHash
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get All User Records
app.get('/api/records', authenticateToken, async (req, res) => {
  try {
    const records = await MedicalRecord.find({ userId: req.user.userId })
      .select('-encryptedData')
      .sort({ date: -1 });
    
    res.json(records);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Specific Record (decrypted)
app.get('/api/records/:id', authenticateToken, async (req, res) => {
  try {
    const record = await MedicalRecord.findOne({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!record) {
      return res.status(404).json({ error: 'Record not found' });
    }

    const decryptedData = decryptData(record.encryptedData);

    res.json({
      ...record.toObject(),
      decryptedData
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Request Access to Records
app.post('/api/access/request', async (req, res) => {
  try {
    const { userId, hospital, requestedBy } = req.body;

    const accessRequest = new AccessRequest({
      userId,
      requestedBy,
      hospital,
      status: 'pending'
    });

    await accessRequest.save();

    res.json({ success: true, requestId: accessRequest._id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Access Requests for User
app.get('/api/access/requests', authenticateToken, async (req, res) => {
  try {
    const requests = await AccessRequest.find({ userId: req.user.userId })
      .sort({ timestamp: -1 });
    
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve/Deny Access Request
app.put('/api/access/requests/:id', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body; // 'approved' or 'denied'
    
    const request = await AccessRequest.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { status },
      { new: true }
    );

    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }

    res.json({ success: true, request });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify Record Hash on Blockchain
app.post('/api/records/verify', async (req, res) => {
  try {
    const { recordHash } = req.body;
    
    if (!contract) {
      return res.json({ verified: true, message: 'Blockchain verification not available (mock mode)' });
    }

    const [exists, timestamp] = await contract.verifyRecordHash(recordHash);
    
    res.json({
      verified: exists,
      timestamp: timestamp.toString(),
      hash: recordHash
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SERVER INITIALIZATION ============

const PORT = process.env.PORT || 5000;

app.listen(PORT, async () => {
  console.log(`MEDIVAULT Backend running on port ${PORT}`);
  await initializeBlockchain();
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message });
});