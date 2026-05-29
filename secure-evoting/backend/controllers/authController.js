const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const crypto      = require('crypto');
const nodemailer  = require('nodemailer');
const Voter       = require('../models/Voter');

// ─── Generate JWT ────────────────────────────────────────────────
const generateToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '24h' });

// ─── Mailer setup ─────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 15000,
});


// ─── @POST /api/auth/register ─────────────────────────────────────
const register = async (req, res) => {
  try {
    const { name, email, password, aadhaarNo, dateOfBirth, phone, constituency } = req.body;

    // Validation
    if (!name || !email || !password || !aadhaarNo || !dateOfBirth || !phone) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    // Check duplicates
    const existingEmail   = await Voter.findOne({ email: email.toLowerCase() });
    const existingAadhaar = await Voter.findOne({ aadhaarNo });
    if (existingEmail)   return res.status(400).json({ success: false, message: 'Email already registered.' });
    if (existingAadhaar) return res.status(400).json({ success: false, message: 'Aadhaar number already registered.' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create voter
    const voter = await Voter.create({
      name, email: email.toLowerCase(), password: hashedPassword,
      aadhaarNo, dateOfBirth, phone, constituency: constituency || 'General',
    });

    res.status(201).json({
      success: true,
      message: 'Registration successful! Please verify your email and await admin approval.',
      voterId: voter._id,
    });
  } catch (error) {
    console.error('Register Error:', error);
    res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
};

// ─── @POST /api/auth/send-otp ─────────────────────────────────────
const sendOtp = async (req, res) => {
  try {
    const { email } = req.body;
    const voter = await Voter.findOne({ email: email.toLowerCase() });
    if (!voter) return res.status(404).json({ success: false, message: 'Email not registered.' });

    // Generate 6-digit OTP
    const otp       = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    voter.otp       = await bcrypt.hash(otp, 8);
    voter.otpExpiry = otpExpiry;
    await voter.save();

    // Send email
    await transporter.sendMail({
      from:    `"Secure E-Voting System" <${process.env.EMAIL_USER}>`,
      to:      voter.email,
      subject: '🗳️ Your E-Voting OTP',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;padding:24px;border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#1A3C6E;">🗳️ Secure E-Voting System</h2>
          <p>Hello <strong>${voter.name}</strong>,</p>
          <p>Your One-Time Password (OTP) for login is:</p>
          <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#C00000;text-align:center;padding:16px;background:#f5f5f5;border-radius:6px;">
            ${otp}
          </div>
          <p style="margin-top:16px;">This OTP is valid for <strong>10 minutes</strong>. Do not share it with anyone.</p>
          <p style="color:#888;font-size:12px;">If you did not request this, please ignore this email.</p>
        </div>`,
    });

    res.json({ success: true, message: `OTP sent to ${voter.email}` });
  } catch (error) {
    console.error('SendOTP Error:', error);
    res.status(500).json({ success: false, message: 'Failed to send OTP.' });
  }
};

// ─── @POST /api/auth/verify-otp ──────────────────────────────────
const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const voter = await Voter.findOne({ email: email.toLowerCase() });
    if (!voter)            return res.status(404).json({ success: false, message: 'User not found.' });
    if (!voter.otp)        return res.status(400).json({ success: false, message: 'No OTP requested.' });
    if (voter.otpExpiry < new Date()) return res.status(400).json({ success: false, message: 'OTP expired.' });

    const isMatch = await bcrypt.compare(otp, voter.otp);
    if (!isMatch) return res.status(400).json({ success: false, message: 'Invalid OTP.' });

    voter.isVerified = true;
    voter.otp        = undefined;
    voter.otpExpiry  = undefined;
    await voter.save();

    res.json({ success: true, message: 'Email verified successfully!' });
  } catch (error) {
    console.error('VerifyOTP Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
};

// ─── @POST /api/auth/login ────────────────────────────────────────
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    const voter = await Voter.findOne({ email: email.toLowerCase() });
    if (!voter) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

    const isMatch = await bcrypt.compare(password, voter.password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

    if (!voter.isVerified) return res.status(403).json({ success: false, message: 'Please verify your email first.' });
    if (!voter.isApproved && voter.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Account pending admin approval.' });
    }

    const token = generateToken(voter._id);

    res.json({
      success: true,
      message: 'Login successful!',
      token,
      voter: {
        _id:          voter._id,
        name:         voter.name,
        email:        voter.email,
        role:         voter.role,
        constituency: voter.constituency,
        isApproved:   voter.isApproved,
      },
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
};

// ─── @GET /api/auth/me ────────────────────────────────────────────
const getMe = async (req, res) => {
  try {
    const voter = await Voter.findById(req.voter._id)
      .select('-password -otp -otpExpiry')
      .populate('votedElections', 'title status');
    res.json({ success: true, voter });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
};

module.exports = { register, sendOtp, verifyOtp, login, getMe };
