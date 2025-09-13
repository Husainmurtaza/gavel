import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Avatar from '@mui/material/Avatar';
import { authenticatedFetch } from '../../utils/api';
import { API_ENDPOINTS } from '../../config/api';

const initialProfile = {
  firstName: '',
  lastName: '',
  email: '',
  avatar: '',
};

const Profile = () => {
  const [profile, setProfile] = useState(initialProfile);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  
  useEffect(() => {
    const fetchProfile = async () => {
      try {
        // Get user data from localStorage
        const userData = JSON.parse(localStorage.getItem('user'));
        if (userData) {
          setProfile({
            firstName: userData.firstName || '',
            lastName: userData.lastName || '',
            email: userData.email || '',
            avatar: ''
          });
        }
        setLoading(false);
      } catch (err) {
        setError('Failed to load profile');
        setLoading(false);
      }
    };
    
    fetchProfile();
  }, []);

  const handleChange = (e) => {
    setProfile({ ...profile, [e.target.name]: e.target.value });
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);
    
    try {
      const response = await authenticatedFetch('/api/admin/profile', {
        method: 'PUT',
        body: JSON.stringify({
          firstName: profile.firstName,
          lastName: profile.lastName,
          email: profile.email
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        // Update local storage with new profile data
        const userData = JSON.parse(localStorage.getItem('user')) || {};
        const updatedUserData = {
          ...userData,
          firstName: profile.firstName,
          lastName: profile.lastName,
          email: profile.email
        };
        localStorage.setItem('user', JSON.stringify(updatedUserData));
        
        setSuccess(true);
        setTimeout(() => setSuccess(false), 3000);
      } else {
        const errorData = await response.json();
        setError(errorData.message || 'Failed to update profile');
      }
    } catch (err) {
      setError('An error occurred while updating profile');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-gradient-to-br from-indigo-50 via-blue-50 to-white">
      <Sidebar />
      <main className="flex-1 flex flex-col items-center justify-center p-0 md:p-12">
        <div className="w-full max-w-3xl mx-auto bg-white shadow-2xl rounded-3xl flex flex-col md:flex-row overflow-hidden border-l-8 border-indigo-500">
          {/* Left: Avatar and Title */}
          <div className="flex flex-col items-center justify-center bg-gradient-to-b from-indigo-100 to-blue-100 p-8 md:w-1/3 w-full">
            <Avatar src={profile.avatar} sx={{ width: 120, height: 120, mb: 3, boxShadow: 3, border: '4px solid #6366f1' }} />
            <span className="text-2xl md:text-3xl font-extrabold text-indigo-700 mb-2">Admin Profile</span>
            <span className="text-sm text-indigo-400 font-medium">Manage your account</span>
          </div>
          {/* Right: Editable Form */}
          <div className="flex-1 p-8 md:p-12 flex flex-col justify-center">
            <form className="flex flex-col gap-8" onSubmit={handleSave}>
              <TextField
                label="First Name"
                name="firstName"
                value={profile.firstName}
                onChange={handleChange}
                fullWidth
                required
                InputLabelProps={{ style: { color: '#6366f1', fontWeight: 600 } }}
                margin="normal"
              />
              <TextField
                label="Last Name"
                name="lastName"
                value={profile.lastName}
                onChange={handleChange}
                fullWidth
                required
                InputLabelProps={{ style: { color: '#6366f1', fontWeight: 600 } }}
                margin="normal"
              />
              <TextField
                label="Email"
                name="email"
                value={profile.email}
                onChange={handleChange}
                fullWidth
                required
                type="email"
                InputLabelProps={{ style: { color: '#6366f1', fontWeight: 600 } }}
              />
       
              {error && (
                <div className="bg-red-50 text-red-700 p-3 rounded-md mb-4 border border-red-200">
                  {error}
                </div>
              )}
              
              {success && (
                <div className="bg-green-50 text-green-700 p-3 rounded-md mb-4 border border-green-200">
                  Profile updated successfully!
                </div>
              )}
              
              <Button
                type="submit"
                disabled={loading}
                sx={{
                  background: 'linear-gradient(90deg, #6366f1 0%, #60a5fa 100%)',
                  color: '#fff',
                  fontWeight: 700,
                  fontSize: '1.1rem',
                  boxShadow: 3,
                  borderRadius: 2,
                  textTransform: 'none',
                  py: 1.5,
                  mt: 2,
                  '&:hover': {
                    background: 'linear-gradient(90deg, #4f46e5 0%, #3b82f6 100%)',
                  },
                }}
                fullWidth
              >
                Save Changes
              </Button>
            </form>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Profile;