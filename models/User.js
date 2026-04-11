const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    googleId: { type: String, required: true, unique: true },
    name:     { type: String },
    email:    { type: String, required: true, unique: true },
    picture:  { type: String },

    // Role system
    role: {
      type: String,
      enum: ['user', 'worker', 'admin'],
      default: 'user',
    },

    // Worker fields (only relevant when role === 'worker')
    workerProfile: {
      isAvailable:  { type: Boolean, default: true },
      assignedTasks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Report' }],
      completedTasks: { type: Number, default: 0 },
      area: { type: String, default: '' },
    },

    // Gamification
    points:       { type: Number, default: 0, index: true },
    totalReports: { type: Number, default: 0 },
    badges:       { type: [String], default: [] },
    lastActivity: { type: Date, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', userSchema);