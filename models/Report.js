const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema(
  {
    description: {
      type: String,
      required: [true, 'Description is required'],
      trim: true,
      maxlength: [300, 'Description cannot exceed 300 characters'],
    },
    category: {
      type: String,
      required: [true, 'Category is required'],
    enum: ['plastic', 'organic', 'electronic', 'paper', 'metal', 'glass', 'batteries', 'lightbulbs', 'chemical', 'medical', 'textiles', 'furniture', 'garden', 'oil', 'construction', 'other'],
    lowercase: true,
    },
    location: {
      type: { type: String, enum: ['Point'], default: 'Point' },
      coordinates: { type: [Number], required: true }, // [lng, lat]
      address:     { type: String, trim: true, default: '' },
    },
    images: [
      {
        url:      { type: String, required: true },
        publicId: { type: String, required: true },
      },
    ],
    status: {
      type: String,
      enum: ['pending', 'in-progress', 'resolved', 'rejected'],
      default: 'pending',
    },
    reportedBy: { type: String, default: 'Anonymous' },

    // User association
    userId:    { type: String, default: null, index: true },
    userEmail: { type: String, default: null },
    userName:  { type: String, default: null },

    // Priority (from previous implementation)
    priorityScore: { type: Number, default: null, min: 0, max: 100 },
    priorityLevel: { type: String, enum: ['High', 'Medium', 'Low', null], default: null },
    priorityBreakdown: {
      resourceScore:  { type: Number, default: null },
      locationScore:  { type: Number, default: null },
      weatherScore:   { type: Number, default: null },
      sentimentScore: { type: Number, default: null },
      materials:      { type: [String], default: [] },
      weatherDetails: { type: mongoose.Schema.Types.Mixed, default: null },
      sentimentLabel: { type: String, default: null },
    },

    // NEW: AI Waste Classification
    wasteClassification: {
      wasteType:                   { type: String, default: null },
      subType:                     { type: String, default: null },
      hazardLevel:                 { type: String, enum: ['Low', 'Medium', 'High', 'Critical', null], default: null },
      disposalMethod:              { type: String, default: null },
      recyclingPossibility:        { type: String, enum: ['Yes', 'No', 'Partial', null], default: null },
      recyclingInstructions:       { type: String, default: null },
      environmentalImpact:         { type: String, default: null },
      estimatedDecompositionDays:  { type: Number, default: null },
      actionRequired:              { type: String, default: null },
    },

    // NEW: Smart Recommendations
    recommendations: {
      immediateActions:       { type: [String], default: [] },
      authorityToContact:     { type: String, default: null },
      contactMethod:          { type: String, default: null },
      estimatedResolutionTime:{ type: String, default: null },
      preventionTips:         { type: [String], default: [] },
      communityRole:          { type: String, default: null },
      recyclingCenters:       { type: mongoose.Schema.Types.Mixed, default: [] },
    },

    // NEW: Escalation tracking
    escalated:        { type: Boolean, default: false },
    escalationReason: { type: String, default: null },
    escalatedAt:      { type: Date, default: null },

    // NEW: Cluster detection
    clusterSize:    { type: Number, default: 1 },
    clusterBoosted: { type: Boolean, default: false },

    // NEW: Worker assignment
    assignedWorker: {
      workerId:   { type: String, default: null },
      workerName: { type: String, default: null },
      assignedAt: { type: Date, default: null },
    },
  },
  { timestamps: true }
);

reportSchema.index({ location: '2dsphere' });
reportSchema.index({ category: 1, status: 1 });
reportSchema.index({ createdAt: -1 });
reportSchema.index({ priorityScore: -1 });

module.exports = mongoose.model('Report', reportSchema);