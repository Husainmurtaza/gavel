import { useState, useEffect } from "react";
import { FaGavel } from "react-icons/fa";
import { HiMenu, HiX } from "react-icons/hi";
import { Link, useNavigate } from "react-router-dom";
import {  LogOut } from "lucide-react";
import { logout, authenticatedFetch } from "../../utils/api";
import "../../../src/index.css";
export default function ClientNavbar() {
  const [isOpen, setIsOpen] = useState(false);
  const toggleMenu = () => setIsOpen(!isOpen);
  const navigate = useNavigate();

  useEffect(() => {
    async function checkSession() {
      try {
        const res = await authenticatedFetch("/api/protected/client");
        if (res.ok) {
          // Session is valid
        } else if (res.status === 403) {
          localStorage.removeItem("client_logged_in");
          navigate("/login");
        }
      } catch (error) {
        console.error('Authentication check failed:', error);
        localStorage.removeItem("client_logged_in");
        navigate("/login");
      }
    }
    checkSession();
  }, [navigate]);

  const links = [
    { name: "Home", path: "/dashboard" },
    { name: "Profile", path: "/client-profile" },
  ];

  const handleLogout = async () => {
    try {
      await logout();
      localStorage.removeItem("client_logged_in");
      navigate("/login");
    } catch (err) {
      localStorage.removeItem("client_logged_in");
      navigate("/login");
    }
  };

  return (
    <header className="w-full bg-white shadow-sm">
      <div className="max-w-7xl mx-auto flex items-center justify-between py-4 px-6 relative">
        {/* Logo */}
        <Link to="/" className="flex items-center space-x-2 absolute left-6 top-1/2 transform -translate-y-1/2">
          <FaGavel className="text-blue-600 text-2xl" />
          <span className="text-xl font-bold text-blue-600">Gavel</span>
        </Link>

        {/* Desktop Navigation - centered, logout at right end */}
        <div className="hidden md:flex flex-1 items-center justify-center relative">
          <nav className="space-x-8 flex">
            {links.map((link) => (
              <Link
                key={link.name}
                to={link.path}
                className="text-gray-700 hover:text-blue-600 font-medium text-lg"
              >
                {link.name}
              </Link>
            ))}
          </nav>
      
        </div>
        <button
            onClick={handleLogout}
            className="flex items-end  gap-1 px-3 py-1.5 border border-red-500 text-red-500 rounded-md text-sm hover:bg-red-50 hidden-sm cursor-pointer"
          >
               <LogOut className="w-4 h-4" />
               Sign Out
          </button>
        {/* Mobile Menu Toggle - right side */}
        <div className="md:hidden absolute right-6 top-1/2 transform -translate-y-1/2">
          <button onClick={toggleMenu} className="text-2xl text-gray-700 cursor-pointer">
            {isOpen ? <HiX /> : <HiMenu />}
          </button>
        </div>
      </div>

      {/* Mobile Navigation Panel - centered */}
      {isOpen && (
        <div className="md:hidden flex flex-col items-center space-y-3 pb-4">
          {links.map((link) => (
            <Link
              key={link.name}
              to={link.path}
              onClick={() => setIsOpen(false)}
              className="text-gray-700 hover:text-blue-600 font-medium text-lg"
            >
              {link.name}
            </Link>
          ))}
               <button
            onClick={handleLogout}
            className="flex items-end  gap-1 px-3 py-1.5 border border-red-500 text-red-500 rounded-md text-sm hover:bg-red-50 cursor-pointer"
          >
               <LogOut className="w-4 h-4" />
               Sign Out
          </button>
        </div>
      )}
    </header>
  );
}
