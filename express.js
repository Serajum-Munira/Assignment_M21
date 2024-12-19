// Assignment: User Data Registration Project using Express.js (Backend only)

// Project Requirements:
// - User Registration API
// - User Login API
// - User Authentication with JWT Token + Cookie
// - User Single Profile Read API
// - All User Profiles Read API
// - Single User Profile Update API
// - Delete Single User API

// Mongoose Schema Fields (Mandatory):
// - firstName
// - lastName
// - NIDNumber
// - phoneNumber
// - password
// - bloodGroup

// Setup
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/userDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Mongoose Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  NIDNumber: { type: String, required: true, unique: true },
  phoneNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  bloodGroup: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Register API
app.post('/register', async (req, res) => {
  try {
    const { firstName, lastName, NIDNumber, phoneNumber, password, bloodGroup } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, NIDNumber, phoneNumber, password: hashedPassword, bloodGroup });
    await user.save();
    res.status(201).send('User registered successfully');
  } catch (error) {
    res.status(500).send('Registration failed');
  }
});

// Login API
app.post('/login', async (req, res) => {
  try {
    const { phoneNumber, password } = req.body;
    const user = await User.findOne({ phoneNumber });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send('Invalid credentials');
    }
    const token = jwt.sign({ id: user._id }, 'secretkey', { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true }).send('Login successful');
  } catch (error) {
    res.status(500).send('Login failed');
  }
});

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).send('Unauthorized');

  jwt.verify(token, 'secretkey', (err, decoded) => {
    if (err) return res.status(403).send('Invalid token');
    req.userId = decoded.id;
    next();
  });
};

// Get Single User Profile API
app.get('/user', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).send('User not found');
    res.json(user);
  } catch (error) {
    res.status(500).send('Error fetching user profile');
  }
});

// Get All Users API
app.get('/users', authenticate, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).send('Error fetching users');
  }
});

// Update Single User API
app.put('/user', authenticate, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(req.userId, updates, { new: true }).select('-password');
    if (!user) return res.status(404).send('User not found');
    res.json(user);
  } catch (error) {
    res.status(500).send('Error updating user');
  }
});

// Delete Single User API
app.delete('/user', authenticate, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.userId);
    res.send('User deleted successfully');
  } catch (error) {
    res.status(500).send('Error deleting user');
  }
});

// Start Server
app.listen(3000, () => console.log('Server running on port 3000'));
