const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Event = require('../models/Event');

// Middleware to authenticate requests
const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Register route
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    user = new User({
      name,
      email,
      password,
      role: 'user',
    });

    await user.save();

    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({
      msg: 'Registration successful',
      token,
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid email or password' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid email or password' });
    }

    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      msg: 'Login successful',
      token,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Fetch registered events
router.get('/registered-events', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('registeredEvents');
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    res.status(200).json(user.registeredEvents);
  } catch (err) {
    console.error('Error fetching registered events:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Update user details
router.put('/update', auth, async (req, res) => {
  const { name, email, phone, college, profilePicture, password } = req.body;

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    // Update fields
    user.name = name || user.name;
    user.email = email || user.email;
    user.phone = phone || user.phone;
    user.college = college || user.college;
    user.profilePicture = profilePicture || user.profilePicture;
    if (password) {
      user.password = password; // Will be hashed by pre-save middleware
    }

    await user.save();

    // Generate new token with updated user details
    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      msg: 'User details updated successfully',
      token,
    });
  } catch (err) {
    console.error('Error updating user details:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = router;