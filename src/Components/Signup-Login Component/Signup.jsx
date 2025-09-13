import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff } from "lucide-react";
import MainNavbar from "../../Header-Footer/Header";
import { API_ENDPOINTS } from "../../config/api";

const SignupForm = () => {
  const navigate = useNavigate();
  const [toast, setToast] = useState({ show: false, message: "", type: "" });
  const [form, setForm] = useState({
    candidateFirstName: "",
    candidateLastName: "",
    candidateEmail: "",
    candidatePhone: "",
    candidatePassword: ""
  });
  const [showPassword, setShowPassword] = useState({ candidate: false });

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const url = API_ENDPOINTS.SIGNUP_CANDIDATE;
    const payload = {
      firstName: form.candidateFirstName,
      lastName: form.candidateLastName,
      email: form.candidateEmail,
      phone: form.candidatePhone,
      password: form.candidatePassword
    };
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        setToast({ show: true, message: "Signup successful! Redirecting to login...", type: "success" });
        // Redirect to login page after 2 seconds
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        setToast({ show: true, message: data.message || "Signup failed", type: "error" });
      }
    } catch (err) {
      setToast({ show: true, message: "Network error", type: "error" });
    }
    setTimeout(() => setToast({ show: false, message: "", type: "" }), 3000);
  };

  return (
    <div> 
      <MainNavbar />
      <div className="min-h-screen flex items-center justify-center bg-white">
        <div className="w-full max-w-md p-6 bg-white rounded-lg shadow-md">
          <h2 className="text-2xl font-bold text-center text-blue-600 mb-6">
            Sign Up
          </h2>

          {/* Toast */}
          {toast.show && (
            <div className={`mb-4 p-2 rounded text-center ${toast.type === "success" ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
              {toast.message}
            </div>
          )}

          {/* Candidate Form */}
          <form onSubmit={handleSubmit}>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">First Name</label>
              <input type="text" name="candidateFirstName" value={form.candidateFirstName} onChange={handleChange} placeholder="First Name" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
              <input type="text" name="candidateLastName" value={form.candidateLastName} onChange={handleChange} placeholder="Last Name" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input type="email" name="candidateEmail" value={form.candidateEmail} onChange={handleChange} placeholder="your@email.com" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Phone Number</label>
              <input type="tel" name="candidatePhone" value={form.candidatePhone} onChange={handleChange} placeholder="Phone Number" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div className="mb-6 relative">
              <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input type={showPassword.candidate ? "text" : "password"} name="candidatePassword" value={form.candidatePassword} onChange={handleChange} placeholder="********" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
              <button 
                type="button"
                onClick={() => setShowPassword(p => ({ ...p, candidate: !p.candidate }))} 
                className="absolute right-3 top-9 p-1 text-gray-500 hover:text-gray-700 transition-colors"
              >
                {showPassword.candidate ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition cursor-pointer">Sign Up</button>
          </form>

          <p className="text-center text-sm text-gray-600 mt-4">
            Already have an account?{" "}
            <Link to="/login" className="text-blue-600 hover:underline">
              Login
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default SignupForm;
