import { useEffect, useState } from "react";
import ApplicationsTable from "../Components/Application";
import CandidateDashboard from "../Components/dashboard";
import CandidateNavbar from "../Header-Footer/Header";
import { useNavigate } from "react-router-dom";
import LoadingSpinner from "../../Components/LoadingSpinner";
import { authenticatedFetch } from "../../utils/api";


const Candidate = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function checkSession() {
      const candidateFlag = localStorage.getItem("candidate_logged_in");
      if (!candidateFlag) {
        navigate("/login");
        return;
      }
      try {
        const res = await authenticatedFetch("/api/protected/candidate");
        if (res.ok) {
          setLoading(false);
        } else if (res.status === 403) {
          localStorage.removeItem("candidate_logged_in");
          navigate("/login");
        }
      } catch (error) {
        console.error('Authentication check failed:', error);
        localStorage.removeItem("candidate_logged_in");
        navigate("/login");
      }
    }
    checkSession();
  }, [navigate]);

  if (loading) {
    return (
      <div>
        <CandidateNavbar />
        <LoadingSpinner message="Loading dashboard..." />
      </div>
    );
  }

  return (
    <div>
      <CandidateNavbar />
      <CandidateDashboard />
      <ApplicationsTable />
      
    </div>
  );
};

export default Candidate;