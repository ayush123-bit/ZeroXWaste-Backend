const Campaign = require('../models/Campaign');
const CampaignRegistration = require('../models/CampaignRegistration');
const { broadcast, sendToUser } = require('../services/notificationService');
const { sendCampaignEmailBatch } = require('../services/emailService');
const jwt = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

// ── POST /api/campaigns ─────────────────────────────────────────────────────
// Admin creates a campaign → find nearby registered users → notify them
const createCampaign = async (req, res) => {
  try {
    const { name, description, dateTime, latitude, longitude, address, maxParticipants } = req.body;

    if (!name || !description || !dateTime || !latitude || !longitude) {
      return res.status(400).json({
        status: 'error',
        message: 'Required: name, description, dateTime, latitude, longitude',
      });
    }

    const campaign = await Campaign.create({
      name,
      description,
      dateTime: new Date(dateTime),
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)],
        address: address || '',
      },
      maxParticipants: parseInt(maxParticipants) || 100,
    });

    // Find all registered users within 10km of the campaign location
    const nearbyRegistrations = await CampaignRegistration.find({
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(longitude), parseFloat(latitude)],
          },
          $maxDistance: 10000, // 10 km radius
        },
      },
    });

    // Remove duplicates by email (a user may have registered for multiple campaigns)
    const uniqueByEmail = [];
    const seen = new Set();
    for (const reg of nearbyRegistrations) {
      if (!seen.has(reg.email)) {
        seen.add(reg.email);
        uniqueByEmail.push(reg);
      }
    }

    // Send in-app notifications
    const notificationPayload = {
      type: 'CAMPAIGN_CREATED',
      title: '🌿 New Campaign in Your Area',
      message: `${name} — ${new Date(dateTime).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}`,
      campaignId: campaign._id,
      description: description.slice(0, 120),
    };

    // Broadcast to all connected users (admins + users online)
    broadcast(notificationPayload);

    // Also send targeted notifications to specific users who are online
    for (const reg of uniqueByEmail) {
      if (reg.userId) sendToUser(reg.userId, notificationPayload);
    }

    // Send email notifications in background
    setImmediate(async () => {
      if (uniqueByEmail.length > 0) {
        await sendCampaignEmailBatch(uniqueByEmail, campaign);
        // Mark as notified
        await CampaignRegistration.updateMany(
          { _id: { $in: uniqueByEmail.map(r => r._id) } },
          { notified: true }
        );
      }
    });

    return res.status(201).json({
      status: 'success',
      message: `Campaign created. ${uniqueByEmail.length} nearby users will be notified.`,
      data: campaign,
      notifiedCount: uniqueByEmail.length,
    });
  } catch (error) {
    console.error('[Campaign] createCampaign failed:', error.message);
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

// ── GET /api/campaigns ──────────────────────────────────────────────────────
const getAllCampaigns = async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    const query = {};
    if (status) query.status = status;

    const campaigns = await Campaign.find(query)
      .sort({ dateTime: 1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit));

    const total = await Campaign.countDocuments(query);

    return res.status(200).json({
      status: 'success',
      data: campaigns,
      pagination: { total, page: parseInt(page), limit: parseInt(limit) },
    });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

// ── GET /api/campaigns/:id ──────────────────────────────────────────────────
const getCampaignById = async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', message: 'Campaign not found' });

    const participantCount = await CampaignRegistration.countDocuments({ campaignId: req.params.id });

    return res.status(200).json({
      status: 'success',
      data: { ...campaign.toObject(), participantCount },
    });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

// ── GET /api/campaigns/:id/participants ─────────────────────────────────────
const getCampaignParticipants = async (req, res) => {
  try {
    const participants = await CampaignRegistration.find({ campaignId: req.params.id })
      .sort({ createdAt: -1 });
    return res.status(200).json({ status: 'success', data: participants, total: participants.length });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

// ── PATCH /api/campaigns/:id/status ────────────────────────────────────────
const updateCampaignStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const valid = ['upcoming', 'ongoing', 'completed', 'cancelled'];
    if (!valid.includes(status)) {
      return res.status(400).json({ status: 'error', message: `Status must be one of: ${valid.join(', ')}` });
    }
    const campaign = await Campaign.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!campaign) return res.status(404).json({ status: 'error', message: 'Campaign not found' });
    return res.status(200).json({ status: 'success', data: campaign });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

// ── DELETE /api/campaigns/:id ───────────────────────────────────────────────
const deleteCampaign = async (req, res) => {
  try {
    await Campaign.findByIdAndDelete(req.params.id);
    await CampaignRegistration.deleteMany({ campaignId: req.params.id });
    return res.status(200).json({ status: 'success', message: 'Campaign deleted' });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

// ── POST /api/campaigns/register ────────────────────────────────────────────
// User registers their interest — stores location for future matching
const registerInterest = async (req, res) => {
  try {
    const { name, email, phone, latitude, longitude, address, campaignId } = req.body;

    if (!name || !email || !phone || !latitude || !longitude) {
      return res.status(400).json({
        status: 'error',
        message: 'Required: name, email, phone, latitude, longitude',
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ status: 'error', message: 'Invalid email format' });
    }

    const user = extractUser(req);

    const registrationData = {
      name,
      email: email.toLowerCase().trim(),
      phone,
      userId: user?.userId || null,
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)],
        address: address || '',
      },
      notified: false,
    };

    if (campaignId) {
      // Register for a specific campaign
      registrationData.campaignId = campaignId;
      try {

        const existing = await CampaignRegistration.findOne({
          campaignId,
          email: email.toLowerCase().trim(),
        });
        if (existing) {
          return res.status(409).json({
            status: 'error',
            message: 'You have already registered for this campaign.',
          });
        }
        const registration = await CampaignRegistration.create(registrationData);
        await Campaign.findByIdAndUpdate(campaignId, { $inc: { participantCount: 1 } });
        return res.status(201).json({ status: 'success', message: 'Registered successfully!', data: registration });
      } catch (err) {
        if (err.code === 11000) {
          return res.status(409).json({ status: 'error', message: 'You have already registered for this campaign.' });
        }
        throw err;
      }
    } else {
      // Register as a general interested user (for future campaign matching)
      // Use a placeholder campaignId for general interest
      const GENERAL_ID = 'general_interest';
      const existing = await CampaignRegistration.findOne({
        email: email.toLowerCase().trim(),
        campaignId: { $exists: false },
      });

      if (existing) {
        // Update their location
        await CampaignRegistration.findByIdAndUpdate(existing._id, {
          location: registrationData.location,
          phone,
          name,
        });
        return res.status(200).json({ status: 'success', message: 'Your details have been updated.' });
      }

      // For general interest, we use a dummy campaignId — we'll query without it
      const registration = await CampaignRegistration.create({
        ...registrationData,
        campaignId: new (require('mongoose').Types.ObjectId)(),
      });

      return res.status(201).json({
        status: 'success',
        message: 'You are now registered! We will notify you when campaigns are organized in your area.',
        data: registration,
      });
    }
  } catch (error) {
    console.error('[Campaign] registerInterest failed:', error.message);
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

module.exports = {
  createCampaign,
  getAllCampaigns,
  getCampaignById,
  getCampaignParticipants,
  updateCampaignStatus,
  deleteCampaign,
  registerInterest,
};