import React from "react";

const TopBar = () => {
  return (
    <header className="sticky top-0 z-20 w-full bg-white shadow-sm border-b flex items-center justify-between px-8 py-3">
      {/* Left section */}
      <div className="flex items-center gap-4">
        {/* Hamburger menu */}
        <button className="text-2xl text-gray-400 hover:text-indigo-500 focus:outline-none">&#9776;</button>
        {/* Search box */}
        <div className="flex items-center bg-gray-50 rounded-lg px-3 py-1 shadow-sm">
          <input type="text" placeholder="Search here....." className="bg-transparent outline-none border-none text-sm px-2 py-1 w-40" />
          <span className="text-indigo-500 text-lg cursor-pointer ml-1">&#128269;</span>
        </div>
        {/* Grid icon */}
        <span className="text-gray-400 text-xl cursor-pointer ml-2">&#8942;</span>
      </div>
      {/* Right section */}
      <div className="flex items-center gap-5">
        {/* Sun icon */}
        <span className="text-orange-400 text-xl cursor-pointer">&#9728;&#65039;</span>
        {/* Language icon */}
        <span className="text-gray-400 text-xl cursor-pointer">&#127760;</span>
        {/* Fullscreen icon */}
        <span className="text-gray-400 text-xl cursor-pointer">&#9974;</span>
        {/* Notification bell */}
        <span className="text-orange-400 text-xl cursor-pointer">&#128276;</span>
        {/* User avatar and name */}
        <div className="flex items-center gap-2 cursor-pointer">
          <img src="https://randomuser.me/api/portraits/women/44.jpg" alt="User" className="w-8 h-8 rounded-full object-cover border-2 border-indigo-100" />
          <span className="text-gray-700 font-semibold">Olivia</span>
          <span className="text-gray-400 text-xs">&#9660;</span>
        </div>
        {/* Settings icon */}
        <span className="text-gray-400 text-xl cursor-pointer">&#9881;&#65039;</span>
      </div>
    </header>
  );
};

export default TopBar; 