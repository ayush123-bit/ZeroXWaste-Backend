const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const googleLogin = async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    let user = await User.findOne({ googleId: payload.sub });

    if (!user) {
      user = new User({
        googleId: payload.sub,
        name: payload.name,
        email: payload.email,
        picture: payload.picture,
        points: 0,
        totalReports: 0,
        badges: [],
        role: 'user',
      });
      await user.save();
    }

    // CRITICAL: store _id as userId in JWT so gamification can find user
    const jwtToken = jwt.sign(
      {
        userId: user._id.toString(), // MongoDB _id as string
        email: user.email,
        name: user.name,
        role: user.role || 'user',
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('ZeroXtoken', jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 7 * 24 * 3600000,
    });

    res.status(200).json({
      message: 'Login successful',
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        picture: user.picture,
        role: user.role || 'user',
        points: user.points || 0,
      },
    });
  } catch (error) {
    console.error('Google Login Failed:', error.message);
    res.status(401).json({ message: 'Invalid token' });
  }
};

const checkAuth = (req, res) => {
  const token = req.cookies?.ZeroXtoken;

  if (!token) {
    return res.status(401).json({ isAuthenticated: false });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return res.status(200).json({
      isAuthenticated: true,
      user: {
        userId: decoded.userId,
        email: decoded.email,
        name: decoded.name,
        role: decoded.role || 'user',
      },
    });
  } catch (err) {
    return res.status(401).json({ isAuthenticated: false });
  }
};

const logout = (req, res) => {
  res.clearCookie('ZeroXtoken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  });
  res.status(200).json({ message: 'Logged out successfully' });
};


const devLogin = async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: 'Not allowed in production' });
  }

  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(404).json({ message: 'User not found' });

  const jwtToken = jwt.sign(
    { userId: user._id.toString(), email: user.email, name: user.name, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie('ZeroXtoken', jwtToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'Lax',
    maxAge: 7 * 24 * 3600000,
  });

  res.status(200).json({
    message: 'Dev login successful',
    user: { _id: user._id, name: user.name, email: user.email, picture: user.picture, role: user.role },
  });
};

module.exports = { googleLogin, checkAuth, logout, devLogin };