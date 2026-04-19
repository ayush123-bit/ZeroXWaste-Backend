const express = require('express');
const router  = express.Router();
const upload  = require('../middlewares/upload');
const {
  getWorkerDashboard,
  getWorkerTasks,
  submitProof,
} = require('../controllers/workerPortalController');

router.get('/dashboard',                         getWorkerDashboard);
router.get('/tasks',                             getWorkerTasks);
router.post('/submit-proof/:reportId',  upload.single('proof'), submitProof);

module.exports = router;