import { useEffect, useState } from "react";
import { CheckCircle, Clock } from "lucide-react";
import { authenticatedFetch } from "../../utils/api";

const StatCard = ({ icon: Icon, title, value, subtitle, gradient }) => (
  <div className={`w-full max-w-sm h-[150px] ${gradient} rounded-xl px-6 py-5 shadow-md flex flex-col justify-center transition-all duration-200`}> 
    <div className="flex items-center gap-2 mb-2 text-sm font-semibold text-white drop-shadow">
      <Icon className="w-10 h-10 text-white opacity-90" /> 
      <span>{title}</span>
    </div>
    <div className="text-4xl font-bold text-white drop-shadow">{value}</div>
    <div className="text-sm text-blue-100 mt-1">{subtitle}</div>
  </div>
);


const CandidateDashboard = () => {
  const [pendingCount, setPendingCount] = useState(0);
  const [completedCount, setCompletedCount] = useState(0);

  useEffect(() => {
    const fetchInterviews = async () => {
      try {
        const res = await authenticatedFetch("/api/interviews");
        if (!res.ok) throw new Error("Failed to fetch interviews");
        const data = await res.json();
        const interviews = data.interviews || [];
        setPendingCount(interviews.filter(i => i.reviewStatus === "pending").length);
        setCompletedCount(interviews.filter(i => i.reviewStatus === "approved").length);
      } catch (err) {
        setPendingCount(0);
        setCompletedCount(0);
      }
    };
    fetchInterviews();
  }, []);

  return (
    <div className="p-6 bg-white  flex justify-center items-center">
      {/* Stats Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full max-w-2xl justify-items-center items-center mx-auto">
        <StatCard
          icon={CheckCircle}
          title="Completed Interviews"
          value={completedCount}
          subtitle="approved by hiring manager"
          gradient="bg-gradient-to-r from-blue-500 to-purple-500"
        />
        <StatCard
          icon={Clock}
          title="Pending Reviews"
          value={pendingCount}
          subtitle="awaiting hiring manager review"
          gradient="bg-gradient-to-r from-yellow-400 to-orange-500"
        />
      </div>
    </div>

  );
};

export default CandidateDashboard;
