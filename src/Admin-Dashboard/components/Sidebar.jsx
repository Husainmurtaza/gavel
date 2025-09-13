import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  HomeOutlined,
  BarChartOutlined,
  CreditCardOutlined,
  ToolOutlined,
  UserOutlined,
  FileTextOutlined,
  ApartmentOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  LogoutOutlined
} from '@ant-design/icons';
import { logout } from '../../utils/api';

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const links = [
    { to: '/admin', label: 'Dashboard', icon: <HomeOutlined className="text-lg" /> },
    { to: '/admin/clients', label: 'Clients', icon: <BarChartOutlined className="text-lg" /> },
    { to: '/admin/companies', label: 'Companies', icon: <ApartmentOutlined className="text-lg" /> },
    { to: '/admin/candidates', label: 'Candidates', icon: <CreditCardOutlined className="text-lg" /> },
    { to: '/admin/positions', label: 'Positions', icon: <ToolOutlined className="text-lg" /> },
    { to: '/admin/transcripts', label: 'Transcripts', icon: <FileTextOutlined className="text-lg" /> },
  ];
  const settingsLinks = [
    { to: '/admin/profile', label: 'Profile', icon: <UserOutlined className="text-lg" /> },
  ];
  const activeClass =
    'bg-blue-50 text-blue-700 font-semibold rounded-lg px-3 py-2 flex items-center gap-3 transition-all duration-200 hover:scale-105';
  const defaultClass =
    'text-gray-600 hover:bg-gray-50 hover:text-blue-600 rounded-lg px-3 py-2 flex items-center gap-3 transition-all duration-200 hover:scale-105';

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/login');
    } catch (err) {
      // Optionally show error toast
    }
  };

  return (
    <aside
      className={`bg-white shadow-xl border-r border-gray-100 rounded-tr-2xl rounded-br-2xl min-h-screen flex flex-col items-center py-6 transition-all duration-300 ease-in-out relative ${collapsed ? 'w-20 px-2' : 'w-64 px-4'}`}
    >
      {/* Logo and App Name */}
      <div className={`flex items-center gap-2 mb-10 group cursor-pointer transition-all duration-200 ${collapsed ? 'justify-center w-full' : ''}`}>
        <div className="bg-indigo-100 rounded-lg p-2 group-hover:bg-indigo-200 group-hover:scale-110 transition-all duration-200 flex-shrink-0">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#6366F1" /></svg>
        </div>
        <span className={`text-xl font-bold text-gray-800 tracking-wide group-hover:text-indigo-700 transition-all duration-200 ${collapsed ? 'opacity-0 scale-95 w-0 overflow-hidden' : 'opacity-100 scale-100 w-auto'}`}>Admin</span>
      </div>
      
      {/* Collapse Toggle Button */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-6 w-6 h-6 bg-white border-2 border-gray-200 rounded-full hover:bg-blue-50 hover:border-blue-300 hover:shadow-lg text-gray-600 transition-all duration-200 z-20 flex items-center justify-center"
        title={collapsed ? "Expand Sidebar" : "Collapse Sidebar"}
      >
        <div className="w-3 h-3 flex items-center justify-center">
          {collapsed ? <MenuUnfoldOutlined className="text-xs" /> : <MenuFoldOutlined className="text-xs" />}
        </div>
      </button>
      {/* Main Section */}
      <div className="w-full">
        <div className={`text-xs font-bold text-gray-400 uppercase mb-2 pl-3 transition-all duration-200 ${collapsed ? 'opacity-0 scale-95' : 'opacity-100 scale-100'}`}>Main</div>
        <nav className="flex flex-col gap-2">
          {links.map(link => (
            <Link
              key={link.to}
              to={link.to}
              className={`${location.pathname === link.to ? activeClass : defaultClass} ${collapsed ? 'justify-center px-2' : ''}`}
              title={collapsed ? link.label : ''}
            >
              <div className="flex items-center justify-center w-5 h-5">
                {link.icon}
              </div>
              <span className={`transition-all duration-200 ${collapsed ? 'opacity-0 scale-95 w-0 overflow-hidden' : 'opacity-100 scale-100 w-auto'}`}>{link.label}</span>
       
            </Link>
          ))}
        </nav>
        <div className={`text-xs font-bold text-gray-400 uppercase mt-8 mb-2 pl-3 transition-all duration-200 ${collapsed ? 'opacity-0 scale-95' : 'opacity-100 scale-100'}`}>Settings</div>
        <nav className="flex flex-col gap-2">
          {settingsLinks.map(link => (
            <Link
              key={link.to}
              to={link.to}
              className={`${location.pathname === link.to ? activeClass : defaultClass} ${collapsed ? 'justify-center px-2' : ''}`}
              title={collapsed ? link.label : ''}
            >
              <div className="flex items-center justify-center w-5 h-5">
                {link.icon}
              </div>
              <span className={`transition-all duration-200 ${collapsed ? 'opacity-0 scale-95 w-0 overflow-hidden' : 'opacity-100 scale-100 w-auto'}`}>{link.label}</span>
            </Link>
          ))}
        </nav>
      </div>
      {/* Logout Button */}
      <button
        onClick={handleLogout}
        className={`mt-auto w-full mb-2 px-3 py-2 bg-red-50 text-red-600 rounded-lg hover:bg-red-100 hover:shadow-md hover:scale-105 font-semibold flex items-center justify-center gap-2 transition-all duration-200 ${collapsed ? 'justify-center px-2' : ''}`}
      >
        <div className="flex items-center justify-center w-5 h-5 flex-shrink-0">
          <LogoutOutlined className="text-lg" />
        </div>
        <span className={`transition-all duration-200 ${collapsed ? 'opacity-0 scale-95 w-0 overflow-hidden' : 'opacity-100 scale-100 w-auto'}`}>Logout</span>
      </button>
    </aside>
  );
};

export default Sidebar;
