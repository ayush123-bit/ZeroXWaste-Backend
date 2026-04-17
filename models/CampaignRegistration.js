const mongoose = require('mongoose');

const registrationSchema = new mongoose.Schema(
  {
    campaignId: {
      type: mongoose.Schema.Types.ObjectId,
      ref:  'Campaign',
      required: true,
    },
    userId:  { type: String, default: null },
    name:    { type: String, required: true, trim: true },
    email:   { type: String, required: true, lowercase: true, trim: true },
    phone:   { type: String, required: true, trim: true },
    location: {
      type:        { type: String, enum: ['Point'], default: 'Point' },
      coordinates: { type: [Number], required: true }, // [lng, lat]
      address:     { type: String, default: '' },
    },
    notified: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// Prevent duplicate registrations for the same user on the same campaign
registrationSchema.index({ campaignId: 1, email: 1 }, { unique: true });
registrationSchema.index({ location: '2dsphere' });

module.exports = mongoose.model('CampaignRegistration', registrationSchema);