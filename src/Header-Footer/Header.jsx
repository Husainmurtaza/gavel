import { useState } from "react";
import { FaGavel } from "react-icons/fa";
import { HiMenu, HiX } from "react-icons/hi";
import { Link } from "react-router-dom";

export default function MainNavbar() {
  const [isOpen, setIsOpen] = useState(false);
  const toggleMenu = () => setIsOpen(!isOpen);

  const links = [
    { name: "Home", path: "/" },
    { name: "About", path: "/about" },
    { name: "Pricing", path: "/pricing" },
    { name: "Help", path: "/help" },
    { name: "Contact", path: "/contact" },
    { name: "Login", path: "/login" },

    
  ];

  return (
    <header className="w-full bg-white shadow-sm">
      <div className="max-w-7xl mx-auto flex items-center justify-between py-4 px-6 relative">
        {/* Logo */}
        <Link to="/" className="flex items-center space-x-2 absolute left-6 top-1/2 transform -translate-y-1/2">
          <FaGavel className="text-blue-600 text-2xl" />
          <span className="text-xl font-bold text-blue-600">Gavel</span>
        </Link>

        {/* Desktop Navigation - centered */}
        <nav className="hidden md:flex mx-auto space-x-8">
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
        </div>
      )}
    </header>
  );
}
