import React from "react";
import { Link } from "react-router-dom";

const Navbar = () => {
  return (
    <nav className="w-full bg-white shadow-sm border-b flex items-center justify-between px-8 py-3">
      {/* Logo area */}
      <div className="flex items-center gap-2">
        <span className="text-blue-600 text-2xl font-bold">Gavel</span>
      </div>
      {/* Navigation links */}
      <div className="flex items-center gap-6">
        <Link to="/" className="text-gray-700 hover:text-blue-600 font-medium">Home</Link>
        <Link to="/about" className="text-gray-700 hover:text-blue-600 font-medium">About</Link>
        <Link to="/pricing" className="text-gray-700 hover:text-blue-600 font-medium">Pricing</Link>
        <Link to="/help" className="text-gray-700 hover:text-blue-600 font-medium">Help</Link>
      </div>
      {/* Placeholder for user actions */}
      <div className="flex items-center gap-4">
        <Link to="/login" className="text-blue-600 font-semibold hover:underline">Login</Link>
        <Link to="/signup" className="bg-blue-600 text-white px-4 py-1.5 rounded-lg font-semibold hover:bg-blue-700 transition">Sign Up</Link>
      </div>
    </nav>
  );
};

export default Navbar; 