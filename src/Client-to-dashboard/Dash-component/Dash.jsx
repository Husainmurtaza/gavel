import React, { useEffect, useState } from "react";
import { Briefcase, UserCheck, Eye, X, Calendar, User, Building, FileText, Clock, AlertCircle } from "lucide-react";
import { authenticatedFetch } from "../../utils/api";

const ClientDashboard = () => {
  const [interviews, setInterviews] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedInterview, setSelectedInterview] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);

  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      setError(null);
      try {
        // Fetch interviews for the logged-in client using the client-specific endpoint
        const intRes = await authenticatedFetch("/api/client/interviews");
        if (!intRes.ok) {
          if (intRes.status === 403) {
            throw new Error("Access denied. Please check your permissions.");
          } else if (intRes.status === 404) {
            throw new Error("No company found for this client account.");
          } else {
            throw new Error(`Failed to fetch interviews: ${intRes.status}`);
          }
        }
        const intData = await intRes.json();
        console.log("Interviews data received:", intData); // Debug log
        
        if (intData && Array.isArray(intData.interviews)) {
          setInterviews(intData.interviews);
        } else {
          console.warn("Invalid interviews data format:", intData);
          setInterviews([]);
        }
      } catch (err) {
        console.error("Error fetching interviews:", err);
        setError(err.message);
        setInterviews([]);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  // Calculate stats with validation
  const totalPositions = interviews.length > 0 ? new Set(interviews.map(i => i.positionId)).size : 0;
  const interviewsCompleted = interviews.filter(i => i.reviewStatus === 'approved').length;
  const pendingInterviews = interviews.filter(i => i.reviewStatus === 'pending').length;
  const rejectedInterviews = interviews.filter(i => i.reviewStatus === 'rejected').length;

  // Prepare recent interviews (latest 5) with validation
  const recentInterviews = interviews
    .filter(interview => interview && interview.createdAt) // Filter out invalid interviews
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 5);

  const handleViewInterview = (interview) => {
    setSelectedInterview(interview);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setSelectedInterview(null);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'approved':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'rejected':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Date not available';
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (err) {
      console.error('Error formatting date:', err);
      return 'Invalid date';
    }
  };

  // Retry function for failed data fetch
  const retryFetch = () => {
    setError(null);
    setLoading(true);
    // Re-trigger useEffect
    window.location.reload();
  };

  return (
    <div className="bg-white px-4 sm:px-8 py-6">
      {/* Error Display */}
      {error && (
        <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <AlertCircle className="w-5 h-5 text-red-400 mr-3" />
            <div className="flex-1">
              <h3 className="text-sm font-medium text-red-800">Error Loading Data</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
            <button
              onClick={retryFetch}
              className="ml-4 bg-red-100 hover:bg-red-200 text-red-800 text-sm font-medium px-3 py-1 rounded-md transition-colors cursor-pointer"
            >
              Retry
            </button>
          </div>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Total Interviews */}
        <div className="bg-gradient-to-br from-blue-400 via-blue-500 to-blue-700 p-6 rounded-2xl shadow-lg text-center transition-transform transform hover:scale-105 hover:shadow-2xl">
          <div className="flex items-center justify-center gap-3 text-blue-100 font-semibold mb-2">
            <Briefcase className="w-6 h-6" />
            Total Interviews
          </div>
          <div className="text-4xl font-extrabold text-white">{loading ? '-' : interviews.length}</div>
          <div className="text-base text-blue-100 mt-1">candidates interviewed</div>
        </div>
        {/* Interviews Completed */}
        <div className="bg-gradient-to-br from-green-400 via-green-500 to-green-700 p-6 rounded-2xl shadow-lg text-center transition-transform transform hover:scale-105 hover:shadow-2xl">
          <div className="flex items-center justify-center gap-3 text-green-100 font-semibold mb-2">
            <UserCheck className="w-6 h-6" />
            Approved
          </div>
          <div className="text-4xl font-extrabold text-white">{loading ? '-' : interviewsCompleted}</div>
          <div className="text-base text-green-100 mt-1">interviews approved</div>
        </div>
        {/* Pending Interviews */}
        <div className="bg-gradient-to-br from-yellow-400 via-yellow-500 to-yellow-700 p-6 rounded-2xl shadow-lg text-center transition-transform transform hover:scale-105 hover:shadow-2xl">
          <div className="flex items-center justify-center gap-3 text-yellow-100 font-semibold mb-2">
            <Clock className="w-6 h-6" />
            Pending
          </div>
          <div className="text-4xl font-extrabold text-white">{loading ? '-' : pendingInterviews}</div>
          <div className="text-base text-yellow-100 mt-1">awaiting review</div>
        </div>
        {/* Rejected Interviews */}
        <div className="bg-gradient-to-br from-red-400 via-red-500 to-red-700 p-6 rounded-2xl shadow-lg text-center transition-transform transform hover:scale-105 hover:shadow-2xl">
          <div className="flex items-center justify-center gap-3 text-red-100 font-semibold mb-2">
            <X className="w-6 h-6" />
            Rejected
          </div>
          <div className="text-4xl font-extrabold text-white">{loading ? '-' : rejectedInterviews}</div>
          <div className="text-base text-red-100 mt-1">interviews rejected</div>
        </div>
      </div>

      {/* Recent Interviews Table */}
      <div className="bg-gradient-to-r from-blue-100 via-purple-100 to-purple-200 rounded-2xl shadow-lg p-1">
        <div className="bg-white rounded-xl p-6 md:p-10">
          <h2 className="text-lg md:text-xl font-semibold text-blue-600 mb-6">Recent Interviews</h2>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead>
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider bg-gray-50">Position</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider bg-gray-50">Candidate</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider bg-gray-50">Interview Date</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider bg-gray-50">Status</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider bg-gray-50">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {loading && (
                  <tr>
                    <td colSpan="5" className="px-6 py-8 text-center">
                      <div className="flex items-center justify-center">
                        <div className="w-8 h-8 border-3 border-blue-600 border-t-transparent rounded-full animate-spin mr-3"></div>
                        <span className="text-gray-600 font-medium">Loading interviews...</span>
                      </div>
                    </td>
                  </tr>
                )}
                {!loading && !error && recentInterviews.length === 0 && (
                  <tr>
                    <td colSpan="5" className="px-6 py-12 text-center text-gray-400">
                      <div className="py-8">
                        <Briefcase className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                        <p className="text-gray-500 text-lg font-medium mb-2">No interviews found yet.</p>
                        <p className="text-sm text-gray-400">Interviews will appear here once candidates complete them.</p>
                      </div>
                    </td>
                  </tr>
                )}
                {!loading && !error && recentInterviews.map((interview, idx) => (
                  <tr key={interview._id || idx} className="hover:bg-gray-50 transition-all duration-200 group">
                    <td className="px-6 py-5">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mr-3">
                          <Briefcase className="w-5 h-5 text-blue-600" />
                        </div>
                        <div>
                          <div className="text-sm font-semibold text-gray-900 group-hover:text-blue-600 transition-colors">
                            {interview.positionName || 'Position not specified'}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-5">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 w-10 h-10 bg-green-100 rounded-full flex items-center justify-center mr-3">
                          <User className="w-5 h-5 text-green-600" />
                        </div>
                        <div>
                          <div className="text-sm font-semibold text-gray-900">
                            {interview.email || 'Email not available'}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-5 whitespace-nowrap">
                      <div className="flex items-center">
                        <Calendar className="w-4 h-4 text-gray-400 mr-2" />
                        <span className="text-sm text-gray-900 font-medium">
                          {formatDate(interview.createdAt)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-5 whitespace-nowrap">
                      <span className={`inline-flex items-center px-3 py-1.5 rounded-full text-xs font-semibold border-2 ${getStatusColor(interview.reviewStatus || interview.status)}`}>
                        {interview.reviewStatus || interview.status || 'pending'}
                      </span>
                    </td>
                    <td className="px-6 py-5 whitespace-nowrap">
                      <button
                        onClick={() => handleViewInterview(interview)}
                        className="inline-flex items-center px-4 py-2.5 border border-transparent text-sm font-semibold rounded-lg text-white bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all duration-200 shadow-md hover:shadow-lg transform hover:-translate-y-0.5 cursor-pointer"
                      >
                        <Eye className="w-4 h-4 mr-2" />
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Interview Details Modal */}
      {modalOpen && selectedInterview && (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="bg-white rounded-3xl shadow-2xl max-w-5xl w-full max-h-[90vh] overflow-y-auto transform transition-all duration-300 scale-100">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-8 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white">
              <div>
                <h3 className="text-2xl font-bold text-gray-900 mb-2">Interview Details</h3>
                <div className="flex items-center space-x-2">
                  <Briefcase className="w-5 h-5 text-blue-600" />
                  <p className="text-lg text-gray-600">
                    {selectedInterview.positionName || 'Position not specified'}
                  </p>
                </div>
              </div>
              <button
                onClick={closeModal}
                className="text-gray-400 hover:text-gray-600 transition-colors duration-200 p-2 hover:bg-gray-100 rounded-full cursor-pointer"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-8">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                {/* Candidate Information */}
                <div className="space-y-6">
                  <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-6 rounded-2xl border border-blue-200">
                    <h4 className="font-bold text-blue-900 mb-4 flex items-center text-lg">
                      <User className="w-5 h-5 mr-3" />
                      Candidate Information
                    </h4>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between p-3 bg-white rounded-lg border border-blue-200">
                        <span className="text-blue-700 font-medium">Email:</span>
                        <span className="text-blue-900 font-semibold">
                          {selectedInterview.email || 'Not available'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-purple-50 to-purple-100 p-6 rounded-2xl border border-purple-200">
                    <h4 className="font-bold text-purple-900 mb-4 flex items-center text-lg">
                      <Clock className="w-5 h-5 mr-3" />
                      Interview Status
                    </h4>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between p-3 bg-white rounded-lg border border-purple-200">
                        <span className="text-purple-700 font-medium">Status:</span>
                        <span className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-semibold border-2 ${getStatusColor(selectedInterview.reviewStatus || selectedInterview.status)}`}>
                          {selectedInterview.reviewStatus || selectedInterview.status || 'pending'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-3 bg-white rounded-lg border border-purple-200">
                        <span className="text-purple-700 font-medium">Created:</span>
                        <span className="text-purple-900 font-semibold">
                          {formatDate(selectedInterview.createdAt)}
                        </span>
                      </div>
                      {selectedInterview.updatedAt && (
                        <div className="flex items-center justify-between p-3 bg-white rounded-lg border border-purple-200">
                          <span className="text-purple-700 font-medium">Updated:</span>
                          <span className="text-purple-900 font-semibold">
                            {formatDate(selectedInterview.updatedAt)}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Additional Information */}
                <div className="space-y-6">
                  <div className="bg-gradient-to-br from-green-50 to-green-100 p-6 rounded-2xl border border-green-200">
                    <h4 className="font-bold text-green-900 mb-4 flex items-center text-lg">
                      <Building className="w-5 h-5 mr-3" />
                      Position Information
                    </h4>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between p-3 bg-white rounded-lg border border-green-200">
                        <span className="text-green-700 font-medium">Position Name:</span>
                        <span className="text-green-900 font-semibold">
                          {selectedInterview.positionName || 'Not available'}
                        </span>
                      </div>
                    </div>
                  </div>

           
                </div>
              </div>

              {/* Interview Content */}
              {(selectedInterview.summary || selectedInterview.transcript) && (
                <div className="border-t border-gray-200 pt-8">
                  <h4 className="font-bold text-gray-900 mb-6 flex items-center text-xl">
                    <FileText className="w-6 h-6 mr-3 text-blue-600" />
                    Interview Content
                  </h4>
                  
                  {selectedInterview.summary && (
                    <div className="mb-6">
                      <h5 className="text-lg font-semibold text-gray-700 mb-3">Summary</h5>
                      <div className="bg-gray-50 p-6 rounded-xl text-gray-800 border border-gray-200">
                        {typeof selectedInterview.summary === 'string' 
                          ? selectedInterview.summary 
                          : JSON.stringify(selectedInterview.summary, null, 2)
                        }
                      </div>
                    </div>
                  )}

                  {selectedInterview.transcript && (
                    <div>
                      <h5 className="text-lg font-semibold text-gray-700 mb-3">Transcript</h5>
                      <div className="bg-gray-50 p-6 rounded-xl text-gray-800 max-h-60 overflow-y-auto border border-gray-200">
                        {typeof selectedInterview.transcript === 'string' 
                          ? selectedInterview.transcript 
                          : JSON.stringify(selectedInterview.transcript, null, 2)
                        }
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end p-8 border-t border-gray-200 bg-gradient-to-r from-gray-50 to-white">
              <button
                onClick={closeModal}
                className="px-6 py-3 text-sm font-semibold text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition-all duration-200 shadow-sm hover:shadow-md cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ClientDashboard;
