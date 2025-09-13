import { useState } from "react";
import Sidebar from "../components/Sidebar";
import Dashboard from "../components/Dashboard";

const AdminDashboard = () => {
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
    return (
        <div className="flex min-h-screen bg-gray-50">
          <Sidebar collapsed={sidebarCollapsed} />
          <div className="flex-1 flex flex-col">
            <Dashboard />
          </div>
        </div>
    )
}

export default AdminDashboard;