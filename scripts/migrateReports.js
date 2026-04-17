// scripts/migrateReports.js - Run this once to add progress stages to existing reports
const mongoose = require('mongoose');
const Report = require('../models/Report');

const migrateReports = async () => {
  try {
    await mongoose.connect("mongodb+srv://userayush:1234@cluster0.p7zfp.mongodb.net/ZeroWasteX");
    
    // First, fix any invalid priorityScore values
    console.log('Fixing invalid priorityScore values...');
    await Report.updateMany(
      { priorityScore: { $gt: 100 } },
      { $set: { priorityScore: 100 } }
    );
    console.log('Fixed priorityScore values > 100');
    
    await Report.updateMany(
      { priorityScore: { $lt: 0 } },
      { $set: { priorityScore: 0 } }
    );
    console.log('Fixed priorityScore values < 0');
    
    const reports = await Report.find({ progressStages: { $exists: false } });
    console.log(`Found ${reports.length} reports without progress stages`);
    
    for (const report of reports) {
      // Fix priorityScore if still invalid
      if (report.priorityScore > 100) report.priorityScore = 100;
      if (report.priorityScore < 0) report.priorityScore = 0;
      
      // Define default stages
      const stages = [
        { name: 'Report Submitted', completed: true, completedAt: report.createdAt, description: 'Your complaint has been registered' },
        { name: 'Initial Review', completed: false, description: 'Authorities are reviewing your complaint' },
        { name: 'Worker Assigned', completed: false, description: 'A worker has been assigned to handle this' },
        { name: 'Work in Progress', completed: false, description: 'Cleanup work is ongoing' },
        { name: 'Quality Check', completed: false, description: 'Final verification in progress' },
        { name: 'Resolved', completed: false, description: 'Complaint has been resolved' }
      ];
      
      // Update stages based on current status
      let progressPercentage = 0;
      let currentStage = 'Report Submitted';
      
      if (report.status === 'pending') {
        stages[0].completed = true;
        progressPercentage = 17;
        currentStage = 'Report Submitted';
      } 
      else if (report.status === 'in-progress') {
        stages[0].completed = true;
        stages[1].completed = true;
        stages[2].completed = true;
        progressPercentage = 50;
        currentStage = 'Work in Progress';
      }
      else if (report.status === 'resolved') {
        stages.forEach(s => s.completed = true);
        progressPercentage = 100;
        currentStage = 'Resolved';
      }
      
      report.progressStages = stages;
      report.progressPercentage = progressPercentage;
      report.currentStage = currentStage;
      
      // Save with validation bypass for priorityScore
      await report.save({ validateBeforeSave: false });
      console.log(`Updated report ${report._id} - Status: ${report.status}, Progress: ${progressPercentage}%`);
    }
    
    console.log('Migration completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
};

migrateReports();