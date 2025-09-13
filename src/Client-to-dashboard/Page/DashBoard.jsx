import { useEffect, useState } from "react";
import ClientDashboard from "../Dash-component/Dash";
import ClientNavbar from "../Header-Footer/Header";
import { useNavigate } from "react-router-dom";
import LoadingSpinner from "../../Components/LoadingSpinner";
import { authenticatedFetch } from "../../utils/api";

const Dashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function checkSession() {
      const clientFlag = localStorage.getItem("client_logged_in");
      if (!clientFlag) {
        navigate("/login");
        return;
      }
      try {
        const res = await authenticatedFetch("/api/protected/client");
        if (res.ok) {
          setLoading(false);
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

  if (loading) {
    return (
      <div>
        <ClientNavbar />
        <LoadingSpinner message="Loading dashboard..." />
      </div>
    );
  }

  return (
    <div>
      <ClientNavbar />
      <ClientDashboard />
    </div>
  );
};

export default Dashboard;