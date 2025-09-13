import { useState } from "react";
import { FaGavel } from "react-icons/fa";
import { HiMenu, HiX } from "react-icons/hi";
import { Link, useNavigate } from "react-router-dom";
import "../../../src/index.css";
import {  LogOut } from "lucide-react";
import { logout } from "../../utils/api";
export default function CandidateNavbar() {
  const [isOpen, setIsOpen] = useState(false);
  const toggleMenu = () => setIsOpen(!isOpen);
  const navigate = useNavigate();

  const links = [
    { name: "Home", path: "/candidate" },
    { name: "Interview", path: "/interview" },
    { name: "Profile", path: "/candidate-profile" },
  ];

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
    } catch (err) {
      navigate("/login");
    }
  };

  return (  
   <header className="w-full bg-white shadow-sm">
  <div className="max-w-7xl mx-auto flex items-center justify-between py-4 px-4 sm:px-6 relative">
    {/* Logo */}
    <Link
      to="/"
      className="flex items-center space-x-2 absolute left-4 top-1/2 transform -translate-y-1/2"
    >
      <FaGavel className="text-blue-600 text-2xl" />
      <span className="text-xl font-bold text-blue-600">Gavel</span>
    </Link>

    {/* Centered Navigation (Desktop only) */}
    <div className="hidden md:flex flex-1 justify-center items-center">
      <nav className="flex gap-6">
        {links.map((link) => (
          <Link
            key={link.name}
            to={link.path}
            className="text-gray-700 hover:text-blue-600 font-medium text-lg transition-colors duration-200"
          >
            {link.name}
          </Link>
        ))}
        <Link
          to="/transcripts"
          className="text-gray-700 hover:text-blue-600 font-medium text-lg transition-colors duration-200"
        >
          Transcript
        </Link>
      </nav>
    </div>

    {/* Logout Button (Desktop only) */}
    <div className="hidden md:flex absolute right-4 top-1/2 transform -translate-y-1/2">
      <button
        onClick={handleLogout}
        className="flex items-center gap-2 px-3 py-1.5 border border-black-500 text-red-500 rounded-md text-sm hover:bg-red-50 transition-all cursor-pointer"
      >
        <LogOut className="w-4 h-4" />
        Sign Out
      </button>
    </div>

    {/* Mobile Menu Toggle */}
    <div className="md:hidden absolute right-4 top-1/2 transform -translate-y-1/2">
      <button onClick={toggleMenu} className="text-2xl text-gray-700 cursor-pointer">
        {isOpen ? <HiX /> : <HiMenu />}
      </button>
    </div>
  </div>

  {/* Mobile Navigation */}
  {isOpen && (
    <div className="md:hidden px-4 pb-4">
      <div className="flex flex-col items-center space-y-3">
        {links.map((link) => (
          <Link
            key={link.name}
            to={link.path}
            onClick={() => setIsOpen(false)}
            className="text-gray-700 hover:text-blue-600 font-medium text-lg transition"
          >
            {link.name}
          </Link>
        ))}
        <Link
          to="/transcripts"
          onClick={() => setIsOpen(false)}
          className="text-gray-700 hover:text-blue-600 font-medium text-lg transition"
        >
          Transcript
        </Link>
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 px-3 py-1.5 border border-red-500 text-red-500 rounded-md text-sm hover:bg-red-50 transition cursor-pointer"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </div>
  )}
</header>

  );
}
