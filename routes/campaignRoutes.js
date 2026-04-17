const express = require('express');
const router  = express.Router();
const {
  createCampaign,
  getAllCampaigns,
  getCampaignById,
  getCampaignParticipants,
  updateCampaignStatus,
  deleteCampaign,
  registerInterest,
} = require('../controllers/campaignController');

router.get('/',                         getAllCampaigns);
router.post('/',                        createCampaign);
router.post('/register',               registerInterest);
router.get('/:id',                     getCampaignById);
router.get('/:id/participants',        getCampaignParticipants);
router.patch('/:id/status',            updateCampaignStatus);
router.delete('/:id',                  deleteCampaign);

module.exports = router;