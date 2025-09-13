import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff } from "lucide-react";
import MainNavbar from "../../Header-Footer/Header";
import { ToastContainer, toast } from 'react-toastify';
import { authenticatedFetch, testBackendConnection } from "../../utils/api";
import { API_ENDPOINTS } from "../../config/api";
import 'react-toastify/dist/ReactToastify.css';

const LoginForm = () => {
  const [activeTab, setActiveTab] = useState("client");
  const [form, setForm] = useState({
    clientEmail: "",
    clientPassword: "",
    candidateEmail: "",
    candidatePassword: ""
  });
  const [showPassword, setShowPassword] = useState({ client: false, candidate: false });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Test backend connection first
    testBackendConnection();
    
    // On mount, check for session and redirect if already logged in
    async function checkSession() {
      const adminFlag = localStorage.getItem("admin_logged_in");
      const clientFlag = localStorage.getItem("client_logged_in");
      const candidateFlag = localStorage.getItem("candidate_logged_in");
      if (adminFlag) {
        try {
          const res = await authenticatedFetch("/api/protected/admin");
          if (res.ok) {
            navigate("/admin");
            return;
          } else {
            localStorage.removeItem("admin_logged_in");
          }
        } catch (error) {
          localStorage.removeItem("admin_logged_in");
        }
      }
      if (clientFlag) {
        try {
          const res = await authenticatedFetch("/api/protected/client");
          if (res.ok) {
            navigate("/dashboard");
            return;
          } else {
            localStorage.removeItem("client_logged_in");
          }
        } catch (error) {
          localStorage.removeItem("client_logged_in");
        }
      }
      if (candidateFlag) {
        try {
          const res = await authenticatedFetch("/api/protected/candidate");
          if (res.ok) {
            navigate("/candidate");
            return;
          } else {
            localStorage.removeItem("candidate_logged_in");
          }
        } catch (error) {
          localStorage.removeItem("candidate_logged_in");
        }
      }
    }
    checkSession();
  }, [navigate]);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    let url = "";
    let payload = {};
    if (activeTab === "client") {
      // Admin login check
      if (form.clientEmail === "admin@gmail.com" && form.clientPassword === "admin123") {
        url = API_ENDPOINTS.LOGIN_ADMIN;
        payload = {
          email: form.clientEmail,
          password: form.clientPassword
        };
      } else {
        url = API_ENDPOINTS.LOGIN_CLIENT;
        payload = {
          email: form.clientEmail,
          password: form.clientPassword
        };
      }
    } else {
      url = API_ENDPOINTS.LOGIN_CANDIDATE;
      payload = {
        email: form.candidateEmail,
        password: form.candidatePassword
      };
    }
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        toast.success(data.message);
        setLoading(false);
        
        // Store access token and user info
        if (data.accessToken) {
          localStorage.setItem("accessToken", data.accessToken);
          localStorage.setItem("user", JSON.stringify(data.user));
        }
        
        // Set localStorage flag immediately
        if (activeTab === "client") {
          if (form.clientEmail === "admin@gmail.com" && form.clientPassword === "admin123") {
            localStorage.setItem("admin_logged_in", "true");
          } else {
            localStorage.setItem("client_logged_in", "true");
          }
        } else {
          localStorage.setItem("candidate_logged_in", "true");
        }
        
        // Navigate after a small delay to ensure cookie is set
        if (data.redirect) {
          setTimeout(() => {
            navigate(data.redirect);
          }, 100);
        }
      } else {
        let msg = data.message ? data.message.toLowerCase() : '';
        let errorMsg = (msg.includes('invalid') || msg.includes('not exist') || msg.includes('does not exist'))
          ? 'Invalid Email Or Password'
          : (data.message || 'Login failed');
        toast.error(errorMsg);
        setLoading(false);
      }
    } catch (err) {
      toast.error("Network error");
      setLoading(false);
    }
  };

  return (
    <div>
      <MainNavbar />
      <ToastContainer position="top-right" autoClose={3000} hideProgressBar={false} newestOnTop closeOnClick pauseOnFocusLoss draggable pauseOnHover />
      <div className="min-h-screen flex items-center justify-center bg-white">
        <div className="w-full max-w-md p-6 bg-white rounded-lg shadow-md">
          <h2 className="text-2xl font-bold text-center text-blue-600 mb-6">
            {activeTab === "client" ? "Client Portal" : "Candidate Portal"}
          </h2>

          <div className="flex justify-between mb-4 bg-gray-100 rounded overflow-hidden">
            <button
              onClick={() => setActiveTab("client")}
              className={`w-1/2 py-2 font-medium transition cursor-pointer ${
                activeTab === "client"
                  ? "bg-white text-blue-600 shadow"
                  : "text-gray-500"
              }`}
            >
              Login as Client
            </button>
            <button
              onClick={() => setActiveTab("candidate")}
              className={`w-1/2 py-2 font-medium transition cursor-pointer ${
                activeTab === "candidate"
                  ? "bg-white text-blue-600 shadow"
                  : "text-gray-500"
              }`}
            >
              Login as Candidate
            </button>
          </div>

          {/* Test Backend Connection Button */}
          <div className="mb-4 text-center">
            <button
              type="button"
              onClick={testBackendConnection}
              className="px-4 py-2 bg-gray-500 text-white rounded-md hover:bg-gray-600 transition cursor-pointer text-sm"
            >
              Test Backend Connection
            </button>
          </div>

          {/* Client Form */}
          {activeTab === "client" && (
            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                <input type="email" name="clientEmail" value={form.clientEmail} onChange={handleChange} placeholder="your@email.com" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
              </div>
              <div className="mb-6 relative">
                <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                <input type={showPassword.client ? "text" : "password"} name="clientPassword" value={form.clientPassword} onChange={handleChange} placeholder="********" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
                <button 
                  type="button"
                  onClick={() => setShowPassword(p => ({ ...p, client: !p.client }))} 
                  className="absolute right-3 top-9 p-1 text-gray-500 hover:text-gray-700 transition-colors"
                >
                  {showPassword.client ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <button 
                type="submit" 
                disabled={loading}
                className={`w-full py-2 rounded-md transition cursor-pointer ${
                  loading 
                    ? 'bg-gray-400 cursor-not-allowed' 
                    : 'bg-blue-600 hover:bg-blue-700'
                } text-white`}
              >
                {loading ? 'Logging in...' : 'Login as Client'}
              </button>
            </form>
          )}

          {/* Candidate Form */}
          {activeTab === "candidate" && (
            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                <input type="email" name="candidateEmail" value={form.candidateEmail} onChange={handleChange} placeholder="your@email.com" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
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
              <button 
                type="submit" 
                disabled={loading}
                className={`w-full py-2 rounded-md transition cursor-pointer ${
                  loading 
                    ? 'bg-gray-400 cursor-not-allowed' 
                    : 'bg-blue-600 hover:bg-blue-700'
                } text-white`}
              >
                {loading ? 'Logging in...' : 'Login as Candidate'}
              </button>
            </form>
          )}

          <p className="text-center text-sm text-gray-600 mt-4">
            Don't have an account?{" "}
            <Link to="/signup" className="text-blue-600 hover:underline">
              Sign Up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginForm;
