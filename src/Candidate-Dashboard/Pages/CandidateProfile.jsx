import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import CandidateNavbar from "../Header-Footer/Header";
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import LoadingSpinner from "../../Components/LoadingSpinner";
import { authenticatedFetch } from "../../utils/api";

const CandidateProfile = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phone: ""
  });
  const navigate = useNavigate();

  useEffect(() => {
    fetchCandidateData();
  }, []);

  const fetchCandidateData = async () => {
    try {
      const res = await authenticatedFetch("/api/protected/candidate");
      
      if (res.ok) {
        const candidateData = await res.json();
        console.log('Candidate data received:', candidateData); // Debug log
        
        if (candidateData.firstName && candidateData.lastName && candidateData.email && candidateData.phone) {
          setForm({
            firstName: candidateData.firstName || "",
            lastName: candidateData.lastName || "",
            email: candidateData.email || "",
            phone: candidateData.phone || ""
          });
        } else {
          console.log('Missing fields in candidate data:', candidateData); // Debug log
          toast.error("Could not load profile data. Please try logging in again.");
        }
      } else if (res.status === 403) {
        localStorage.removeItem("candidate_logged_in");
        navigate("/login");
        return;
      }
    } catch (err) {
      console.error('Authentication failed:', err);
      localStorage.removeItem("candidate_logged_in");
      navigate("/login");
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);

    try {
      const res = await authenticatedFetch("/api/candidates/profile", {
        method: "PUT",
        body: JSON.stringify(form)
      });

      const data = await res.json();
      
      if (res.ok) {
        toast.success("Profile updated successfully!");
      } else if (res.status === 403) {
        toast.error("Access denied. Please make sure you are logged in as a candidate.");
        console.error('Profile update forbidden:', data.message);
      } else {
        toast.error(data.message || "Failed to update profile");
        console.error('Profile update failed:', data);
      }
    } catch (err) {
      console.error('Profile update error:', err);
      toast.error("Network error. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div>
        <CandidateNavbar />
        <LoadingSpinner message="Loading profile..." />
      </div>
    );
  }

  return (
    <div>
      <CandidateNavbar />
      <ToastContainer position="top-right" autoClose={3000} hideProgressBar={false} newestOnTop closeOnClick pauseOnFocusLoss draggable pauseOnHover />
      
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-2xl mx-auto px-4">
          <div className="bg-white rounded-lg shadow-md p-8">
            <div className="mb-8">
              <h1 className="text-3xl font-bold text-gray-900 mb-2">Profile</h1>
              <p className="text-gray-600">Update your personal information</p>
             
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    First Name
                  </label>
                  <input
                    type="text"
                    name="firstName"
                    value={form.firstName}
                    onChange={handleChange}
                    className="w-full px-4 py-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="First Name"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Last Name
                  </label>
                  <input
                    type="text"
                    name="lastName"
                    value={form.lastName}
                    onChange={handleChange}
                    className="w-full px-4 py-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Last Name"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Email Address
                </label>
                <input
                  type="email"
                  name="email"
                  value={form.email}
                  onChange={handleChange}
                  className="w-full px-4 py-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="your@email.com"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Phone Number
                </label>
                <input
                  type="tel"
                  name="phone"
                  value={form.phone}
                  onChange={handleChange}
                  className="w-full px-4 py-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Phone Number"
                  required
                />
              </div>

              <div className="flex justify-end space-x-4 pt-6">
                <button
                  type="button"
                  onClick={() => navigate("/candidate")}
                  className="px-6 py-3 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className={`px-6 py-3 rounded-md transition cursor-pointer ${
                    saving
                      ? 'bg-gray-400 cursor-not-allowed'
                      : 'bg-blue-600 hover:bg-blue-700'
                  } text-white`}
                >
                  {saving ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CandidateProfile; 