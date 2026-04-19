const express = require('express');
const router  = express.Router();
const upload  = require('../middlewares/upload');
const {
  listWorkers,
  promoteToWorker,
  assignWorkerToReport,
  completeTask,
  submitProofViaWorkerRoute,
  getMyTasks,
} = require('../controllers/workerController');

router.get('/',                            listWorkers);
router.post('/promote/:userId',            promoteToWorker);
router.patch('/assign/:reportId',          assignWorkerToReport);
router.patch('/complete/:reportId',        completeTask);
router.post('/submit-proof/:reportId',     upload.single('proof'), submitProofViaWorkerRoute);
router.get('/my-tasks',                    getMyTasks);

module.exports = router;