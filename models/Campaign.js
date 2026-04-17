const mongoose = require('mongoose');

const campaignSchema = new mongoose.Schema(
  {
    name:        { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    dateTime:    { type: Date,   required: true },
    location: {
      type:        { type: String, enum: ['Point'], default: 'Point' },
      coordinates: { type: [Number], required: true }, // [lng, lat]
      address:     { type: String, default: '' },
    },
    createdBy:   { type: String, default: 'admin' },
    status:      { type: String, enum: ['upcoming', 'ongoing', 'completed', 'cancelled'], default: 'upcoming' },
    maxParticipants: { type: Number, default: 100 },
    participantCount: { type: Number, default: 0 },
  },
  { timestamps: true }
);

campaignSchema.index({ location: '2dsphere' });
campaignSchema.index({ dateTime: 1 });

module.exports = mongoose.model('Campaign', campaignSchema);