import React, { useEffect, useState } from 'react';
import {
  WalletOutlined,
  GlobalOutlined,
  ClockCircleOutlined,
  ShoppingCartOutlined,
} from '@ant-design/icons';
import 'chart.js/auto';
import { FiCalendar, FiBriefcase, FiUsers, FiUserCheck } from "react-icons/fi";
import { useNavigate } from 'react-router-dom';
import { authenticatedFetch } from '../../utils/api';
import { API_ENDPOINTS } from '../../config/api';

const API_POSITIONS = API_ENDPOINTS.POSITIONS;
const API_CLIENTS = API_ENDPOINTS.CLIENTS;
const API_CANDIDATES = API_ENDPOINTS.CANDIDATES;
const API_COMPANIES = API_ENDPOINTS.COMPANIES;
const API_INTERVIEWS = API_ENDPOINTS.ADMIN_INTERVIEWS;

const Dashboard = () => {
  const [clients, setClients] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [companies, setCompanies] = useState([]);
  const [positions, setPositions] = useState([]);
  // Add state for header stats
  const [company, setCompany] = useState(0);
  const [headerPositions, setHeaderPositions] = useState(0);
  const [headerClients, setHeaderClients] = useState(0);
  const [headerCandidates, setHeaderCandidates] = useState(0);
  const [headerLoading, setHeaderLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    setHeaderLoading(true);
    let isMounted = true;
    const fetchData = () => {
      Promise.all([
        authenticatedFetch("/api/admin/interviews").then(res => res.ok ? res.json() : []),
        authenticatedFetch("/api/positions").then(res => res.ok ? res.json() : []),
        authenticatedFetch("/api/clients").then(res => res.ok ? res.json() : []),
        authenticatedFetch("/api/candidates").then(res => res.ok ? res.json() : []),
        authenticatedFetch("/api/companies").then(res => res.ok ? res.json() : []),
      ]).then(([interviews, positionsData, clients, candidates, companies]) => {
        if (!isMounted) return;
        setCompany(Array.isArray(companies) ? companies.length : 0);
        setHeaderPositions(Array.isArray(positionsData) ? positionsData.length : 0);
        setHeaderClients(Array.isArray(clients) ? clients.length : 0);
        setHeaderCandidates(Array.isArray(candidates) ? candidates.length : 0);
        setHeaderLoading(false);
        setClients(Array.isArray(clients) ? clients.slice(0, 5) : []);
        setCandidates(Array.isArray(candidates) ? candidates.slice(0, 5) : []);
        setCompanies(Array.isArray(companies) ? companies : []);
        setPositions(Array.isArray(positionsData) ? positionsData : []);
      });
    };
    fetchData();
    const interval = setInterval(fetchData, 30000); // 30 seconds
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Prepare company data for chart
  const companyClientCounts = companies.map(company => ({
    name: company.name,
    count: clients.filter(client => client.company && (client.company.id === company.id || client.company === company.id)).length
  }));

  const stats = [
    { title: "TODAY'S MONEY", value: "$53,897", change: "+3.48%", icon: <WalletOutlined />, color: 'text-green-500' },
    { title: "TODAY'S USERS", value: "$3,200", change: "+5.2%", icon: <GlobalOutlined />, color: 'text-green-500' },
    { title: "NEW CLIENTS", value: "+2,503", change: "-2.82%", icon: <ClockCircleOutlined />, color: 'text-red-500' },
    { title: "TOTAL SALES", value: "$173,000", change: "+8.12%", icon: <ShoppingCartOutlined />, color: 'text-green-500' },
  ];

  const pageVisits = [
    { key: 1, page: '/argon/', visitors: 4569, users: 340, bounce: '46.53%' },
    { key: 2, page: '/argon/index.html', visitors: 3985, users: 319, bounce: '46.53%' },
    { key: 3, page: '/argon/charts.html', visitors: 3513, users: 294, bounce: '36.49%' },
    { key: 4, page: '/argon/tables.html', visitors: 2050, users: 147, bounce: '50.87%' },
    { key: 5, page: '/argon/profile.html', visitors: 1795, users: 190, bounce: '46.53%' },
  ];

  const socialTraffic = [
    { key: 1, referral: 'Facebook', visitors: 1480, percent: 60 },
    { key: 2, referral: 'Facebook', visitors: 5480, percent: 70 },
    { key: 3, referral: 'Google', visitors: 4807, percent: 80 },
    { key: 4, referral: 'Instagram', visitors: 3678, percent: 75 },
    { key: 5, referral: 'Twitter', visitors: 2645, percent: 30 },
  ];

  const headerStats = [
    {
      label: "Total Candidates",
      value: headerLoading ? "..." : headerCandidates,
      icon: <FiUserCheck className="text-3xl text-orange-500" />, // Candidates
    },
    {
      label: "Total Positions",
      value: headerLoading ? "..." : headerPositions,
      icon: <FiBriefcase className="text-3xl text-purple-500" />, // Positions
    },
    {
      label: "Total Companies",
      value: headerLoading ? "..." : company,
      icon: <FiCalendar className="text-3xl text-blue-500" />, 
    },
    {
      label: "Total Clients",
      value: headerLoading ? "..." : headerClients,
      icon: <FiUsers className="text-3xl text-green-500" />, // Clients
    },
  ];

  // Helper to get client name by id
  const getClientName = (clientId) => {
    const client = clients.find(c => c.id === clientId || c._id === clientId);
    return client ? `${client.firstName} ${client.lastName}` : '—';
  };
  // Add status list for contextual coloring
  const statusList = [
    { label: 'Active', color: 'bg-purple-100 text-purple-700', row: 'bg-purple-50' },
    { label: 'Completed', color: 'bg-green-100 text-green-700', row: 'bg-green-50' },
    { label: 'Pending', color: 'bg-yellow-100 text-yellow-700', row: 'bg-yellow-50' },
    { label: 'Scheduled', color: 'bg-cyan-100 text-cyan-700', row: 'bg-cyan-50' },
  ];
  // Helper to get random status
  const getStatus = (idx) => statusList[idx % statusList.length];
  // Helper to get random avatars for users
  const getAvatars = () => [
    'https://randomuser.me/api/portraits/men/32.jpg',
    'https://randomuser.me/api/portraits/women/44.jpg',
    'https://randomuser.me/api/portraits/men/45.jpg',
  ];

  // Add logical Y-axis labels for the chart
  const logicalLabels = (value) => {
    if (value === 0) return '';
    if (value <= 2) return 'Few';
    if (value <= 5) return 'Some';
    if (value <= 10) return 'Many';
    return 'Most';
  };

  // Helper: Get company initials
  const getInitials = (name) => name ? name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) : '';

  // Helper function to truncate text
  const truncate = (str, n) => (str && str.length > n ? str.slice(0, n) + '...' : str);

  return (
    <div className="flex-1 p-0 bg-white min-h-screen">
      {/* Dashboard Header Section (migrated from AdminDashboardHeader.jsx) */}
      <div className="w-full px-4 py-4">
        <div className="rounded-2xl bg-gradient-to-r from-blue-600 to-blue-400 flex flex-col md:flex-row items-center justify-between p-8 relative overflow-hidden" style={{minHeight: 220}}>
          {/* Left: Greeting and Info */}
          <div className="flex-1 text-white z-10">
            <div className="text-lg mb-1">Good Morning</div>
            <div className="text-3xl font-bold mb-2">Admin</div>
        

          </div>
          {/* Right: Doctor Illustration */}
          <div className="flex-1 flex justify-end items-end z-10">
            <img src="https://assets10.lottiefiles.com/packages/lf20_ktwnwv5m.json" alt="Doctor" className="w-48 h-48 object-contain" style={{maxHeight: 180}} onError={e => e.target.style.display='none'} />
          </div>
          {/* Decorative background shapes */}
          <div className="absolute inset-0 z-0">
            <svg width="100%" height="100%" viewBox="0 0 600 220" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M0 180 Q300 100 600 180" stroke="#fff2" strokeWidth="30" fill="none" />
              <circle cx="550" cy="60" r="8" fill="#fff5" />
              <circle cx="100" cy="40" r="5" fill="#fff5" />
              <circle cx="300" cy="120" r="4" fill="#fff5" />
            </svg>
          </div>
        </div>
        {/* Stats Cards */}
        <div className="flex flex-col md:flex-row gap-4 mt-[-40px] px-2 justify-center items-center">
          {headerStats.map((stat, idx) => (
            <div key={stat.label} className="flex-1 min-w-[200px] max-w-xs bg-white rounded-xl shadow-md p-6 flex flex-col items-start justify-between mx-2 relative z-20">
              <div className="flex items-center justify-between w-full mb-2">
                <span className="text-gray-500 font-medium">{stat.label}</span>
                <span>{stat.icon}</span>
              </div>
              <div className="text-3xl font-bold text-gray-800 mb-1">{stat.value}</div>
            </div>
          ))}
        </div>
      </div>
      {/* Four tables: Clients, Candidates, Positions, Companies (2 per row) */}
      <div className="w-full pt-6 pb-8 px-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 mb-10">
            {/* Latest Candidates */}
          <div className="bg-gradient-to-br from-indigo-50 via-indigo-100 to-indigo-200 rounded-1xl shadow-lg p-8 border border-indigo-200">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold text-indigo-800">Latest Candidates</h2>
              <button className="bg-indigo-600 text-white px-4 py-1 rounded-lg text-sm font-medium shadow hover:bg-indigo-700 transition cursor-pointer" onClick={() => navigate('/admin/candidates')}>View All</button>
            </div>
            <div className="overflow-x-auto rounded-xl">
              <table className="min-w-full text-base text-left rounded-xl overflow-hidden">
                <thead className="bg-gradient-to-r from-indigo-200 via-indigo-100 to-indigo-50 text-indigo-800">
                  <tr>
                    <th className="py-3 px-4 font-semibold">First Name</th>
                    <th className="py-3 px-4 font-semibold">Last Name</th>
                    <th className="py-3 px-4 font-semibold">Email</th>
                    <th className="py-3 px-4 font-semibold">Phone</th>
                  </tr>
                </thead>
                <tbody>
                  {(candidates || []).length === 0 ? (
                    <tr><td colSpan="4" className="py-4 text-center text-indigo-400">No candidates found.</td></tr>
                  ) : (
                    (candidates || []).slice(0, 5).map((candidate, idx) => (
                      <tr key={candidate.id} className={`transition ${idx % 2 === 0 ? 'bg-indigo-50' : 'bg-indigo-100'} hover:bg-indigo-200`}>
                        <td className="py-2 px-4 font-medium">{candidate.firstName}</td>
                        <td className="py-2 px-4">{candidate.lastName}</td>
                        <td className="py-2 px-4">{candidate.email}</td>
                        <td className="py-2 px-4">{candidate.phone}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
              {/* Latest Positions */}
          <div className="bg-gradient-to-br from-green-50 via-green-100 to-green-200 rounded-1xl shadow-lg p-8 border border-green-200 bg-white">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold text-green-800">Latest Positions</h2>
              <button className="bg-green-600 text-white px-4 py-1 rounded-lg text-sm font-medium shadow hover:bg-green-700 transition cursor-pointer" onClick={() => navigate('/admin/positions')}>View All</button>
            </div>
            <div className="overflow-x-auto rounded-xl">
              <table className="min-w-full text-base text-left rounded-xl overflow-hidden">
                <thead className="bg-gradient-to-r from-green-200 via-green-100 to-green-50 text-green-800">
                  <tr>
                    <th className="py-3 px-4 font-semibold">Name</th>
                    <th className="py-3 px-4 font-semibold">Description</th>
                    <th className="py-3 px-4 font-semibold">Company</th>
                  </tr>
                </thead>
                <tbody>
                  {(positions || []).length === 0 ? (
                    <tr><td colSpan="3" className="py-4 text-center text-green-400">No positions found.</td></tr>
                  ) : (
                    (positions || []).slice(0, 5).map((pos, idx) => (
                      <tr key={pos.id} className={`transition ${idx % 2 === 0 ? 'bg-green-50' : 'bg-green-100'} hover:bg-green-200`}>
                        <td className="py-2 px-4 font-medium">{pos.name}</td>
                        <td className="py-2 px-4">{truncate(pos.projectDescription, 30)}</td>
                        <td className="py-2 px-4">{pos.companyName || '-'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
      
        
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
      
          {/* Latest Companies */}
          <div className="bg-gradient-to-br from-purple-50 via-purple-100 to-purple-200 rounded-1xl shadow-lg p-8 border border-purple-200 bg-white">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold text-purple-800">Latest Companies</h2>
              <button className="bg-purple-600 text-white px-4 py-1 rounded-lg text-sm font-medium shadow hover:bg-purple-700 transition cursor-pointer" onClick={() => navigate('/admin/companies')}>View All</button>
            </div>
            <div className="overflow-x-auto rounded-xl">
              <table className="min-w-full text-base text-left rounded-xl overflow-hidden">
                <thead className="bg-gradient-to-r from-purple-200 via-purple-100 to-purple-50 text-purple-800">
                  <tr>
                    <th className="py-3 px-4 font-semibold">Name</th>
                  </tr>
                </thead>
                <tbody>
                  {(companies || []).length === 0 ? (
                    <tr><td colSpan="1" className="py-4 text-center text-purple-400">No companies found.</td></tr>
                  ) : (
                    (companies || []).slice(0, 5).map((company, idx) => (
                      <tr key={company.id} className={`transition ${idx % 2 === 0 ? 'bg-purple-50' : 'bg-purple-100'} hover:bg-purple-200`}>
                        <td className="py-2 px-4 font-medium">{company.name}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

              {/* Latest Clients */}
          <div className="bg-gradient-to-br from-blue-50 via-blue-100 to-blue-200 rounded-1xl shadow-lg p-8 border border-blue-200">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold text-blue-800">Latest Clients</h2>
              <button className="bg-blue-600 text-white px-4 py-1 rounded-lg text-sm font-medium shadow hover:bg-blue-700 transition cursor-pointer" onClick={() => navigate('/admin/clients')}>View All</button>
            </div>
            <div className="overflow-x-auto rounded-xl">
              <table className="min-w-full text-base text-left rounded-xl overflow-hidden">
                <thead className="bg-gradient-to-r from-blue-200 via-blue-100 to-blue-50 text-blue-800">
                  <tr>
                    <th className="py-3 px-4 font-semibold">First Name</th>
                    <th className="py-3 px-4 font-semibold">Last Name</th>
                    <th className="py-3 px-4 font-semibold">Email</th>
                    <th className="py-3 px-4 font-semibold">Phone</th>
                  </tr>
                </thead>
                <tbody>
                  {(clients || []).length === 0 ? (
                    <tr><td colSpan="4" className="py-4 text-center text-blue-400">No clients found.</td></tr>
                  ) : (
                    (clients || []).slice(0, 5).map((client, idx) => (
                      <tr key={client.id} className={`transition ${idx % 2 === 0 ? 'bg-blue-50' : 'bg-blue-100'} hover:bg-blue-200`}>
                        <td className="py-2 px-4 font-medium">{client.firstName}</td>
                        <td className="py-2 px-4">{client.lastName}</td>
                        <td className="py-2 px-4">{client.email}</td>
                        <td className="py-2 px-4">{client.phone}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
};

export default Dashboard;
