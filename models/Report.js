const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true,
    maxlength: [300, 'Description cannot exceed 300 characters']
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    enum: ['plastic', 'organic', 'electronic', 'other'],
    lowercase: true
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number],
      required: [true, 'Location coordinates are required']
    },
    address: {
      type: String,
      trim: true
    }
  },
  images: [
    {
      url: {
        type: String,
        required: true
      },
      publicId: {
        type: String,
        required: true
      }
    }
  ],
  status: {
    type: String,
    enum: ['pending', 'in-progress', 'resolved', 'rejected'],
    default: 'pending'
  },
  reportedBy: {
    type: String,
    default: 'Anonymous'
  }
}, {
  timestamps: true
});

// Create geospatial index for location queries
reportSchema.index({ location: '2dsphere' });

// Create index for category and status for faster queries
reportSchema.index({ category: 1, status: 1 });
reportSchema.index({ createdAt: -1 });

const Report = mongoose.model('Report', reportSchema);

module.exports = Report;