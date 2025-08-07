const mongoose = require('mongoose');

const candidateSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'candidate' },
  deleted: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('Candidate', candidateSchema, 'candidate'); 