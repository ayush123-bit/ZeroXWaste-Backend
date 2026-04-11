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
      });
      await user.save();
    }

   const jwtToken = jwt.sign(
  { userId: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.cookie('ZeroXtoken', jwtToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
      maxAge: 3600000
    });

    res.status(200).json({
      message: 'Login successful',
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        picture: user.picture,
        role: user.role  // ✅ role added
      },
      token: jwtToken
    });
  } catch (error) {
    console.error("Google Login Failed:", error.message);
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
      user: decoded, // ✅ this already contains role since we added it to JWT
    });
  } catch (err) {
    console.error("JWT verification failed:", err.message);
    return res.status(401).json({ isAuthenticated: false });
  }
};

module.exports = { googleLogin, checkAuth };