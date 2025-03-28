const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken'); // Add this import
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

// Middleware to check if user is admin
const adminAuth = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ msg: 'Access denied, admin only' });
  }
  next();
};

// Get all events
router.get('/', auth, async (req, res) => {
  try {
    const events = await Event.find().populate('createdBy', 'name email');
    res.status(200).json(events);
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Add new event
router.post('/', [auth, adminAuth], async (req, res) => {
  const { name, type, category, startDate, endDate, description, picture, applyLink } = req.body;

  try {
    const event = new Event({
      name,
      type,
      category,
      startDate,
      endDate,
      description,
      picture,
      applyLink,
      createdBy: req.user.id,
    });

    await event.save();
    res.status(201).json(event);
  } catch (err) {
    console.error('Error adding event:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Update event
router.put('/:id', [auth, adminAuth], async (req, res) => {
  const { name, type, category, startDate, endDate, description, picture, applyLink } = req.body;

  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ msg: 'Event not found' });
    }

    event.name = name || event.name;
    event.type = type || event.type;
    event.category = category || event.category;
    event.startDate = startDate || event.startDate;
    event.endDate = endDate || event.endDate;
    event.description = description || event.description;
    event.picture = picture || event.picture;
    event.applyLink = applyLink || event.applyLink;

    await event.save();
    res.status(200).json(event);
  } catch (err) {
    console.error('Error updating event:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Delete event
router.delete('/:id', [auth, adminAuth], async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ msg: 'Event not found' });
    }

    await event.remove();
    res.status(200).json({ msg: 'Event deleted successfully' });
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = router;