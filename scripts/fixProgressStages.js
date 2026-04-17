// scripts/fixProgressStages.js - Run this once to fix existing reports
const mongoose = require('mongoose');
require('dotenv').config();

const fixProgressStages = async () => {
  try {
    await mongoose.connect("mongodb+srv://userayush:1234@cluster0.p7zfp.mongodb.net/ZeroWasteX");
    
    const db = mongoose.connection.db;
    const reportsCollection = db.collection('reports');
    
    const reports = await reportsCollection.find({}).toArray();
    console.log(`Found ${reports.length} reports to fix`);
    
    for (const report of reports) {
      let stages = [];
      let progressPercentage = 0;
      let currentStage = 'Report Submitted';
      
      // Define stages based on current status
      switch(report.status) {
        case 'pending':
          stages = [
            { name: 'Report Submitted', completed: true, completedAt: report.createdAt || new Date(), description: 'Your complaint has been registered and is pending review' },
            { name: 'Initial Review', completed: false, description: 'Authorities are reviewing your complaint' },
            { name: 'Worker Assigned', completed: false, description: 'A worker has been assigned to handle this' },
            { name: 'Work in Progress', completed: false, description: 'Cleanup work is ongoing at the location' },
            { name: 'Quality Check', completed: false, description: 'Final verification and quality assurance in progress' },
            { name: 'Resolved', completed: false, description: 'Complaint has been resolved and closed' }
          ];
          progressPercentage = 17;
          currentStage = 'Report Submitted';
          break;
          
        case 'in-progress':
          stages = [
            { name: 'Report Submitted', completed: true, completedAt: report.createdAt || new Date(), description: 'Your complaint has been registered and is pending review' },
            { name: 'Initial Review', completed: true, completedAt: new Date(), description: 'Authorities are reviewing your complaint' },
            { name: 'Worker Assigned', completed: true, completedAt: report.assignedWorker?.assignedAt || new Date(), description: 'A worker has been assigned to handle this' },
            { name: 'Work in Progress', completed: false, description: 'Cleanup work is ongoing at the location' },
            { name: 'Quality Check', completed: false, description: 'Final verification and quality assurance in progress' },
            { name: 'Resolved', completed: false, description: 'Complaint has been resolved and closed' }
          ];
          progressPercentage = 50;
          currentStage = 'Work in Progress';
          break;
          
        case 'resolved':
          stages = [
            { name: 'Report Submitted', completed: true, completedAt: report.createdAt || new Date(), description: 'Your complaint has been registered and is pending review' },
            { name: 'Initial Review', completed: true, completedAt: new Date(), description: 'Authorities are reviewing your complaint' },
            { name: 'Worker Assigned', completed: true, completedAt: report.assignedWorker?.assignedAt || new Date(), description: 'A worker has been assigned to handle this' },
            { name: 'Work in Progress', completed: true, completedAt: new Date(), description: 'Cleanup work is ongoing at the location' },
            { name: 'Quality Check', completed: true, completedAt: new Date(), description: 'Final verification and quality assurance in progress' },
            { name: 'Resolved', completed: true, completedAt: report.updatedAt || new Date(), description: 'Complaint has been resolved and closed' }
          ];
          progressPercentage = 100;
          currentStage = 'Resolved';
          break;
          
        case 'rejected':
          stages = [
            { name: 'Report Submitted', completed: true, completedAt: report.createdAt || new Date(), description: 'Your complaint has been registered and is pending review' },
            { name: 'Initial Review', completed: false, description: 'Authorities are reviewing your complaint' },
            { name: 'Worker Assigned', completed: false, description: 'A worker has been assigned to handle this' },
            { name: 'Work in Progress', completed: false, description: 'Cleanup work is ongoing at the location' },
            { name: 'Quality Check', completed: false, description: 'Final verification and quality assurance in progress' },
            { name: 'Resolved', completed: false, description: 'Complaint has been resolved and closed' }
          ];
          progressPercentage = 17;
          currentStage = 'Rejected';
          break;
          
        default:
          stages = [
            { name: 'Report Submitted', completed: true, completedAt: report.createdAt || new Date(), description: 'Your complaint has been registered and is pending review' },
            { name: 'Initial Review', completed: false, description: 'Authorities are reviewing your complaint' },
            { name: 'Worker Assigned', completed: false, description: 'A worker has been assigned to handle this' },
            { name: 'Work in Progress', completed: false, description: 'Cleanup work is ongoing at the location' },
            { name: 'Quality Check', completed: false, description: 'Final verification and quality assurance in progress' },
            { name: 'Resolved', completed: false, description: 'Complaint has been resolved and closed' }
          ];
          progressPercentage = 17;
          currentStage = 'Report Submitted';
      }
      
      await reportsCollection.updateOne(
        { _id: report._id },
        { 
          $set: { 
            progressStages: stages,
            progressPercentage: progressPercentage,
            currentStage: currentStage
          } 
        }
      );
      
      console.log(`Fixed report ${report._id} - Status: ${report.status} → Progress: ${progressPercentage}% (${currentStage})`);
    }
    
    console.log('Migration completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
};

fixProgressStages();