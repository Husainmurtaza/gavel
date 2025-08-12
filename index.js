const express = require('express');
const mongoose = require('mongoose');
const Client = require('./models/client');
const Candidate = require('./models/candidate');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Admin = require('./models/admin');
const Position = require('./models/position');
const Interview = require('./models/interview');
const Company = require('./models/company');

const app = express();
const PORT = process.env.PORT || 5000;

// Add response compression
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://GavelDatabase:j5NmOUB8hi1LfBxI@gavelcluster.p7kueq8.mongodb.net/gavel?retryWrites=true&w=majority&appName=GavelCluster';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Middleware
app.use(express.json());
// CORS configuration with environment support
const corsOrigins = process.env.CORS_ORIGINS 
  ? process.env.CORS_ORIGINS.split(',')
  : [
      'http://localhost:5173',        // Local development
      'http://31.97.232.40:5000',    // Live server
      'https://joingavel.com',
      'https://www.joingavel.com'
    ];

app.use(cors({
  origin: corsOrigins,
  credentials: true
}));
app.use(cookieParser());

// MongoDB Connection with optimized settings
mongoose.connect(MONGO_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
})
  .then(() => {
    console.log('MongoDB connection successful');
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
  });

// Basic route
app.get('/', (req, res) => {
  res.send('Express server is running!');
});

// Debug route to check cookies
app.get('/api/debug/cookies', (req, res) => {
  console.log('Cookies received:', req.cookies);
  console.log('Headers:', req.headers);
  res.json({ 
    cookies: req.cookies,
    hasToken: !!req.cookies.token,
    userAgent: req.headers['user-agent'],
    origin: req.headers.origin
  });
});

// Test route to check authentication
app.get('/api/test-auth', authenticate, (req, res) => {
  res.json({ 
    message: 'Authentication working', 
    user: { id: req.user.id, role: req.user.role } 
  });
});

// Test client profile route
app.get('/api/test-client-profile', authenticate, async (req, res) => {
  console.log('Test client profile - User:', req.user);
  if (req.user.role !== 'client') {
    return res.status(403).json({ message: 'Forbidden - Not a client' });
  }
  try {
    const client = await Client.findById(req.user.id);
    console.log('Client found in test:', client);
    if (!client) {
      return res.status(404).json({ message: 'Client not found in database' });
    }
    res.json({
      message: 'Client found',
      client: {
        id: client._id,
        firstName: client.firstName,
        lastName: client.lastName,
        email: client.email,
        phone: client.phone
      }
    });
  } catch (err) {
    console.log('Error in test client profile:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Test candidate profile route
app.get('/api/test-candidate-profile', authenticate, async (req, res) => {
  console.log('Test candidate profile - User:', req.user);
  if (req.user.role !== 'candidate') {
    return res.status(403).json({ message: 'Forbidden - Not a candidate' });
  }
  try {
    const candidate = await Candidate.findById(req.user.id);
    console.log('Candidate found in test:', candidate);
    if (!candidate) {
      return res.status(404).json({ message: 'Candidate not found in database' });
    }
    res.json({
      message: 'Candidate found',
      candidate: {
        id: candidate._id,
        firstName: candidate.firstName,
        lastName: candidate.lastName,
        email: candidate.email,
        phone: candidate.phone
      }
    });
  } catch (err) {
    console.log('Error in test candidate profile:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Test route to check all clients in database
app.get('/api/test-all-clients', async (req, res) => {
  try {
    const clients = await Client.find({}).select('firstName lastName email phone role _id');
    console.log('All clients in database:', clients);
    res.json({
      message: 'All clients',
      count: clients.length,
      clients: clients
    });
  } catch (err) {
    console.log('Error getting all clients:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Test route to check all candidates in database
app.get('/api/test-all-candidates', async (req, res) => {
  try {
    const candidates = await Candidate.find({}).select('firstName lastName email phone role _id');
    console.log('All candidates in database:', candidates);
    res.json({
      message: 'All candidates',
      count: candidates.length,
      candidates: candidates
    });
  } catch (err) {
    console.log('Error getting all candidates:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Route to refresh JWT token with correct role from database
app.post('/api/refresh-token', authenticate, async (req, res) => {
  try {
    console.log('Refreshing token for user:', req.user);
    
    // Find the user in the appropriate collection based on current role
    let user = null;
    let newRole = null;
    
    if (req.user.role === 'client' || !req.user.role) {
      user = await Client.findById(req.user.id);
      if (user) newRole = 'client';
    } else if (req.user.role === 'candidate') {
      user = await Candidate.findById(req.user.id);
      if (user) newRole = 'candidate';
    } else if (req.user.role === 'admin') {
      user = await Admin.findById(req.user.id);
      if (user) newRole = 'admin';
    }
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Create new token with correct role
    const newToken = jwt.sign({ id: user._id, role: newRole }, JWT_SECRET, { expiresIn: '4h' });
    
    // Set new cookie
    res.cookie('token', newToken, { 
      httpOnly: true, 
      maxAge: 14400000, // 4 hours in milliseconds
      secure: true,
      sameSite: 'none'
    });
    
    console.log('Token refreshed with role:', newRole);
    res.json({ 
      message: 'Token refreshed successfully',
      user: { id: user._id, role: newRole }
    });
  } catch (err) {
    console.log('Error refreshing token:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Auth middleware
function authenticate(req, res, next) {
  console.log('Auth middleware - Cookies:', req.cookies);
  console.log('Auth middleware - Headers:', req.headers);
  
  const token = req.cookies.token;
  if (!token) {
    console.log('No token found in cookies');
    return res.status(401).json({ message: 'Session expired. Please login again.' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    console.log('Authenticated user:', { id: decoded.id, role: decoded.role }); // Debug log
    next();
  } catch (err) {
    console.log('JWT verification failed:', err.message); // Debug log
    return res.status(401).json({ message: 'Session expired. Please login again.' });
  }
}

// Example protected route for client dashboard
app.get('/api/protected/client', authenticate, async (req, res) => {
  console.log('GET /api/protected/client - User:', req.user); // Debug log
  if (req.user.role !== 'client') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const client = await Client.findById(req.user.id).select('firstName lastName email phone _id');
    console.log('Client found:', client); // Debug log
    if (!client) return res.status(404).json({ message: 'Client not found' });
    const response = { 
      id: client._id, 
      firstName: client.firstName, 
      lastName: client.lastName, 
      email: client.email, 
      phone: client.phone 
    };
    console.log('Sending response:', response); // Debug log
    res.json(response);
  } catch (err) {
    console.log('Error in /api/protected/client:', err.message); // Debug log
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Example protected route for candidate dashboard
app.get('/api/protected/candidate', authenticate, async (req, res) => {
  console.log('GET /api/protected/candidate - User:', req.user); // Debug log
  if (req.user.role !== 'candidate') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const candidate = await Candidate.findById(req.user.id).select('firstName lastName email phone _id');
    console.log('Candidate found:', candidate); // Debug log
    if (!candidate) return res.status(404).json({ message: 'Candidate not found' });
    const response = { 
      id: candidate._id, 
      firstName: candidate.firstName, 
      lastName: candidate.lastName, 
      email: candidate.email, 
      phone: candidate.phone 
    };
    console.log('Sending response:', response); // Debug log
    res.json(response);
  } catch (err) {
    console.log('Error in /api/protected/candidate:', err.message); // Debug log
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Signup route for Client
app.post('/api/signup/client', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password } = req.body;
    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const existing = await Client.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'Email already exists. Please use a different email.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const client = new Client({ firstName, lastName, email, phone, password: hashedPassword, role: 'client' });
    await client.save();
    res.status(201).json({ message: 'Client registered successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Signup route for Candidate
app.post('/api/signup/candidate', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password } = req.body;
    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const existing = await Candidate.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'Email already exists. Please use a different email.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const candidate = new Candidate({ firstName, lastName, email, phone, password: hashedPassword, role: 'candidate' });
    await candidate.save();
    res.status(201).json({ message: 'Candidate registered successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Login route for Client
app.post('/api/login/client', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }
  const client = await Client.findOne({ email });
  if (!client) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
  const isMatch = await bcrypt.compare(password, client.password);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
  const clientToken = jwt.sign({ id: client._id, role: 'client' }, JWT_SECRET, { expiresIn: '4h' });
  
  // Cookie settings that work for both local and production
  const isProduction = process.env.NODE_ENV === 'production';
  console.log('Setting client cookie - Production:', isProduction, 'Secure:', isProduction, 'SameSite:', isProduction ? 'none' : 'lax');
  
  res.cookie('token', clientToken, { 
    httpOnly: true, 
    maxAge: 14400000, // 4 hours in milliseconds
    secure: isProduction, // Only use secure in production
    sameSite: isProduction ? 'none' : 'lax' // Use 'none' only in production
  });
  res.json({ message: 'Login successful', redirect: '/dashboard' });
});

// Login route for Candidate
app.post('/api/login/candidate', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }
  const candidate = await Candidate.findOne({ email });
  if (!candidate) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
  const isMatch = await bcrypt.compare(password, candidate.password);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
  const candidateToken = jwt.sign({ id: candidate._id, role: 'candidate' }, JWT_SECRET, { expiresIn: '4h' });
  
  // Cookie settings that work for both local and production
  const isProduction = process.env.NODE_ENV === 'production';
  console.log('Setting candidate cookie - Production:', isProduction, 'Secure:', isProduction, 'SameSite:', isProduction ? 'none' : 'lax');
  
  res.cookie('token', candidateToken, { 
    httpOnly: true, 
    maxAge: 14400000, // 4 hours in milliseconds
    secure: isProduction, // Only use secure in production
    sameSite: isProduction ? 'none' : 'lax' // Use 'none' only in production
  });
  res.json({ message: 'Login successful', redirect: '/candidate' });
});

// Create admin route (for initial setup)
app.post('/api/create-admin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const existing = await Admin.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'Admin already exists.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = new Admin({ email, password: hashedPassword, role: 'admin' });
    await admin.save();
    res.status(201).json({ message: 'Admin created successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Login route for Admin
app.post('/api/login/admin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }
  
  // Special case for admin@gmail.com
  if (email === 'admin@gmail.com') {
    // Check if admin exists, if not create one
    let admin = await Admin.findOne({ email });
    if (!admin) {
      const hashedPassword = await bcrypt.hash(password, 10);
      admin = new Admin({ 
        firstName: 'Admin', 
        lastName: 'User', 
        email, 
        phone: '0000000000', 
        password: hashedPassword, 
        role: 'admin' 
      });
      await admin.save();
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    
    const adminToken = jwt.sign({ id: admin._id, role: 'admin' }, JWT_SECRET, { expiresIn: '4h' });
    
    // Cookie settings that work for both local and production
    const isProduction = process.env.NODE_ENV === 'production';
    console.log('Setting admin cookie - Production:', isProduction, 'Secure:', isProduction, 'SameSite:', isProduction ? 'none' : 'lax');
    
    res.cookie('token', adminToken, { 
      httpOnly: true, 
      maxAge: 14400000, // 4 hours in milliseconds
      secure: isProduction, // Only use secure in production
      sameSite: isProduction ? 'none' : 'lax' // Use 'none' only in production
    });
    res.json({ message: 'Admin login successful', redirect: '/admin' });
    return;
  }
  
  // Regular admin login
  const admin = await Admin.findOne({ email });
  if (!admin) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
  const adminToken = jwt.sign({ id: admin._id, role: 'admin' }, JWT_SECRET, { expiresIn: '4h' });
  
  // Cookie settings that work for both local and production
  const isProduction = process.env.NODE_ENV === 'production';
  console.log('Setting admin cookie - Production:', isProduction, 'Secure:', isProduction, 'SameSite:', isProduction ? 'none' : 'lax');
  
  res.cookie('token', adminToken, { 
    httpOnly: true, 
    maxAge: 14400000, // 4 hours in milliseconds
    secure: isProduction, // Only use secure in production
    sameSite: isProduction ? 'none' : 'lax' // Use 'none' only in production
  });
  res.json({ message: 'Admin login successful', redirect: '/admin' });
});

// Logout route (destroy session)
app.post('/api/logout', (req, res) => {
  console.log('Logging out user'); // Debug log
  const isProduction = process.env.NODE_ENV === 'production';
  res.clearCookie('token', { 
    httpOnly: true, 
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax'
  });
  res.json({ message: 'Logged out successfully' });
});

// Protected route for admin dashboard
app.get('/api/protected/admin', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  // Optionally fetch admin info from DB
  try {
    const admin = await Admin.findById(req.user.id).select('email _id');
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    res.json({ id: admin._id, email: admin.email });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// GET positions: populate company with optimized query
app.get('/api/positions', authenticate, async (req, res) => {
  console.log('GET /api/positions - User:', req.user); // Debug log
  if (req.user.role !== 'admin' && req.user.role !== 'candidate') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const positions = await Position.find({}, { name: 1, projectDescription: 1, company: 1, redFlag: 1 })
      .populate('company', 'name')
      .lean()
      .limit(50); // Limit results for faster response
    res.json(positions.map(pos => ({
      id: pos._id,
      name: pos.name,
      projectDescription: pos.projectDescription,
      company: pos.company ? pos.company._id : '',
      companyName: pos.company ? pos.company.name : '',
      redFlag: pos.redFlag || ''
    })));
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// POST positions: accept company and redFlag
app.post('/api/positions', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { name, projectDescription, company, redFlag } = req.body;
  if (!name) return res.status(400).json({ message: 'Position name is required.' });
  try {
    const position = new Position({ name, projectDescription, company, redFlag });
    await position.save();
    res.status(201).json({ id: position._id, name: position.name, projectDescription: position.projectDescription, company: position.company, redFlag: position.redFlag });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// PUT positions: accept company and redFlag
app.put('/api/positions/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { name, projectDescription, company, redFlag } = req.body;
  if (!name) return res.status(400).json({ message: 'Position name is required.' });
  try {
    const position = await Position.findByIdAndUpdate(
      req.params.id,
      { name, projectDescription, company, redFlag },
      { new: true }
    );
    if (!position) return res.status(404).json({ message: 'Position not found.' });
    res.json({ id: position._id, name: position.name, projectDescription: position.projectDescription, company: position.company, redFlag: position.redFlag });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.delete('/api/positions/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  try {
    const position = await Position.findByIdAndDelete(req.params.id);
    if (!position) return res.status(404).json({ message: 'Position not found.' });
    res.json({ message: 'Position deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// CRUD for Companies (admin only)
app.get('/api/companies', authenticate, async (req, res) => {
  console.log('GET /api/companies - User:', req.user); // Debug log
  if (req.user.role !== 'admin') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const companies = await Company.find({}, { name: 1 });
    res.json(companies.map(c => ({ id: c._id, name: c.name })));
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/companies', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { name } = req.body;
  if (!name) return res.status(400).json({ message: 'Company name is required.' });
  try {
    const existing = await Company.findOne({ name });
    if (existing) return res.status(409).json({ message: 'Company already exists.' });
    const company = new Company({ name });
    await company.save();
    res.status(201).json({ id: company._id, name: company.name });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.put('/api/companies/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { name } = req.body;
  if (!name) return res.status(400).json({ message: 'Company name is required.' });
  try {
    const company = await Company.findByIdAndUpdate(
      req.params.id,
      { name },
      { new: true }
    );
    if (!company) return res.status(404).json({ message: 'Company not found.' });
    res.json({ id: company._id, name: company.name });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.delete('/api/companies/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  try {
    const company = await Company.findByIdAndDelete(req.params.id);
    if (!company) return res.status(404).json({ message: 'Company not found.' });
    res.json({ message: 'Company deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// CRUD for Clients (admin only)
app.get('/api/clients', authenticate, async (req, res) => {
  console.log('GET /api/clients - User:', req.user); // Debug log
  if (req.user.role !== 'admin') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const clients = await Client.find({}, { firstName: 1, lastName: 1, email: 1, phone: 1, company: 1, redFlag: 1 }).populate('company', 'name');
    res.json(clients.map(c => ({
      id: c._id,
      firstName: c.firstName,
      lastName: c.lastName,
      email: c.email,
      phone: c.phone,
      company: c.company ? { id: c.company._id, name: c.company.name } : null,
      redFlag: c.redFlag || ''
    })));
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/clients', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { firstName, lastName, email, phone, password, company, redFlag } = req.body;
  if (!firstName || !lastName || !email || !phone || !password) return res.status(400).json({ message: 'All fields are required.' });
  try {
    const existing = await Client.findOne({ email });
    if (existing) return res.status(409).json({ message: 'Email already exists.' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const client = new Client({ firstName, lastName, email, phone, password: hashedPassword, role: 'client', company, redFlag });
    await client.save();
    res.status(201).json({ id: client._id, firstName: client.firstName, lastName: client.lastName, email: client.email, phone: client.phone, company: client.company, redFlag: client.redFlag });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.put('/api/clients/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { firstName, lastName, email, phone, company, redFlag } = req.body;
  if (!firstName || !lastName || !email || !phone) return res.status(400).json({ message: 'All fields are required.' });
  try {
    const client = await Client.findByIdAndUpdate(req.params.id, { firstName, lastName, email, phone, company, redFlag }, { new: true });
    if (!client) return res.status(404).json({ message: 'Client not found.' });
    res.json({ id: client._id, firstName: client.firstName, lastName: client.lastName, email: client.email, phone: client.phone, company: client.company, redFlag: client.redFlag });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.delete('/api/clients/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  try {
    const client = await Client.findByIdAndDelete(req.params.id);
    if (!client) return res.status(404).json({ message: 'Client not found.' });
    res.json({ message: 'Client deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Client profile GET route
app.get('/api/clients/profile', authenticate, async (req, res) => {
  if (req.user.role !== 'client') return res.status(403).json({ message: 'Forbidden' });
  try {
    const client = await Client.findById(req.user.id).select('firstName lastName email phone _id');
    if (!client) return res.status(404).json({ message: 'Client not found.' });
    res.json({ 
      client: {
        id: client._id,
        firstName: client.firstName,
        lastName: client.lastName,
        email: client.email,
        phone: client.phone
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Client profile update route
app.put('/api/clients/profile', authenticate, async (req, res) => {
  console.log('PUT /api/clients/profile - User:', req.user); // Debug log
  console.log('PUT /api/clients/profile - Body:', req.body); // Debug log
  
  if (req.user.role !== 'client') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  
  const { firstName, lastName, email, phone } = req.body;
  if (!firstName || !lastName || !email || !phone) return res.status(400).json({ message: 'All fields are required.' });
  try {
    // Check if email is already taken by another client
    const existingClient = await Client.findOne({ email, _id: { $ne: req.user.id } });
    if (existingClient) return res.status(409).json({ message: 'Email already exists.' });
    
    const client = await Client.findByIdAndUpdate(
      req.user.id, 
      { firstName, lastName, email, phone }, 
      { new: true }
    );
    if (!client) return res.status(404).json({ message: 'Client not found.' });
    res.json({ 
      message: 'Profile updated successfully.',
      client: {
        id: client._id,
        firstName: client.firstName,
        lastName: client.lastName,
        email: client.email,
        phone: client.phone
      }
    });
  } catch (err) {
    console.log('Error in profile update:', err.message); // Debug log
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// CRUD for Candidates (admin only)
app.get('/api/candidates', authenticate, async (req, res) => {
  console.log('GET /api/candidates - User:', req.user); // Debug log
  if (req.user.role !== 'admin') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const candidates = await Candidate.find({}, { firstName: 1, lastName: 1, email: 1, phone: 1 });
    res.json(candidates.map(c => ({ id: c._id, firstName: c.firstName, lastName: c.lastName, email: c.email, phone: c.phone })));
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Candidate profile GET route
app.get('/api/candidates/profile', authenticate, async (req, res) => {
  console.log('GET /api/candidates/profile - User:', req.user); // Debug log
  if (req.user.role !== 'candidate') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  try {
    const candidate = await Candidate.findById(req.user.id).select('firstName lastName email phone _id');
    console.log('Candidate found:', candidate); // Debug log
    if (!candidate) return res.status(404).json({ message: 'Candidate not found.' });
    const response = { 
      id: candidate._id, 
      firstName: candidate.firstName, 
      lastName: candidate.lastName, 
      email: candidate.email, 
      phone: candidate.phone 
    };
    console.log('Sending response:', response); // Debug log
    res.json(response);
  } catch (err) {
    console.log('Error in /api/candidates/profile:', err.message); // Debug log
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Candidate profile update route
app.put('/api/candidates/profile', authenticate, async (req, res) => {
  console.log('PUT /api/candidates/profile - User:', req.user); // Debug log
  console.log('PUT /api/candidates/profile - Body:', req.body); // Debug log
  
  if (req.user.role !== 'candidate') {
    console.log('Forbidden - User role:', req.user.role); // Debug log
    return res.status(403).json({ message: 'Forbidden' });
  }
  
  const { firstName, lastName, email, phone } = req.body;
  if (!firstName || !lastName || !email || !phone) return res.status(400).json({ message: 'All fields are required.' });
  try {
    // Check if email is already taken by another candidate
    const existingCandidate = await Candidate.findOne({ email, _id: { $ne: req.user.id } });
    if (existingCandidate) return res.status(409).json({ message: 'Email already exists.' });
    
    const candidate = await Candidate.findByIdAndUpdate(
      req.user.id, 
      { firstName, lastName, email, phone }, 
      { new: true }
    );
    if (!candidate) return res.status(404).json({ message: 'Candidate not found.' });
    res.json({ 
      message: 'Profile updated successfully.',
      candidate: {
        id: candidate._id,
        firstName: candidate.firstName,
        lastName: candidate.lastName,
        email: candidate.email,
        phone: candidate.phone
      }
    });
  } catch (err) {
    console.log('Error in candidate profile update:', err.message); // Debug log
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/candidates', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { firstName, lastName, email, phone, password } = req.body;
  if (!firstName || !lastName || !email || !phone || !password) return res.status(400).json({ message: 'All fields are required.' });
  try {
    const existing = await Candidate.findOne({ email });
    if (existing) return res.status(409).json({ message: 'Email already exists.' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const candidate = new Candidate({ firstName, lastName, email, phone, password: hashedPassword, role: 'candidate' });
    await candidate.save();
    res.status(201).json({ id: candidate._id, firstName: candidate.firstName, lastName: candidate.lastName, email: candidate.email, phone: candidate.phone });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.put('/api/candidates/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { firstName, lastName, email, phone } = req.body;
  if (!firstName || !lastName || !email || !phone) return res.status(400).json({ message: 'All fields are required.' });
  try {
    const candidate = await Candidate.findByIdAndUpdate(req.params.id, { firstName, lastName, email, phone }, { new: true });
    if (!candidate) return res.status(404).json({ message: 'Candidate not found.' });
    res.json({ id: candidate._id, firstName: candidate.firstName, lastName: candidate.lastName, email: candidate.email, phone: candidate.phone });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.delete('/api/candidates/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  try {
    const candidate = await Candidate.findByIdAndDelete(req.params.id);
    if (!candidate) return res.status(404).json({ message: 'Candidate not found.' });
    res.json({ message: 'Candidate deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Save interview result (webhook endpoint)
app.post('/api/interviews', async (req, res) => {
  console.log("📥 Received data at /api/interviews:", req.body);
  try {
    const { positionName, candidateId, email, interviewID, positionDescription, positionId, summary, transcript, status } = req.body;
    if (!positionName || !candidateId || !email || !interviewID || !positionId) {
      return res.status(400).json({ message: 'Missing required fields.' });
    }
    const interview = new Interview({
      positionName,
      candidateId,
      email,
      interviewID,
      positionDescription,
      positionId,
      summary,
      transcript,
      status,
      reviewStatus: 'pending'
    });
    await interview.save();
    res.status(201).json({ message: 'Interview saved successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Check if candidate has already applied for a position
app.get('/api/interviews/check', async (req, res) => {
  const { candidateId, positionId } = req.query;
  if (!candidateId || !positionId) {
    return res.status(400).json({ message: 'Missing candidateId or positionId' });
  }
  try {
    const exists = await Interview.exists({ candidateId, positionId });
    res.json({ applied: !!exists });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get all interviews for the logged-in candidate with pagination
app.get('/api/interviews', authenticate, async (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ message: 'Forbidden' });
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const candidateId = String(req.user.id);
    const total = await Interview.countDocuments({ candidateId });
    const interviews = await Interview.find({ candidateId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    res.json({ total, page, limit, interviews });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get a single interview by id for the logged-in candidate
app.get('/api/interviews/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'candidate') return res.status(403).json({ message: 'Forbidden' });
  try {
    const interview = await Interview.findById(req.params.id);
    if (!interview || String(interview.candidateId) !== String(req.user.id)) {
      return res.status(404).json({ message: 'Interview not found' });
    }
    res.json(interview);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: Get all interviews
app.get('/api/admin/interviews', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  try {
    const interviews = await Interview.find({});
    res.json(interviews);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: Approve interview
app.put('/api/admin/interviews/:id/approve', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  try {
    const interview = await Interview.findByIdAndUpdate(
      req.params.id,
      { reviewStatus: 'approved' },
      { new: true }
    );
    res.json(interview);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: Reject interview
app.put('/api/admin/interviews/:id/reject', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  try {
    const interview = await Interview.findByIdAndUpdate(
      req.params.id,
      { reviewStatus: 'rejected' },
      { new: true }
    );
    res.json(interview);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 