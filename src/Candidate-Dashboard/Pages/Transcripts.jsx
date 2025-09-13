import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranscript } from './TranscriptContext';
import CandidateNavbar from '../Header-Footer/Header';
import { authenticatedFetch } from '../../utils/api';

const getReviewStatusBadge = (status) => {
  const baseClasses = "px-2 py-1 rounded-full text-sm font-medium whitespace-nowrap";
  switch (status) {
    case 'pending':
      return <span className={`${baseClasses} bg-yellow-100 text-yellow-800`}>Pending</span>;
    case 'approved':
      return <span className={`${baseClasses} bg-green-100 text-green-800`}>Approved</span>;
    case 'rejected':
      return <span className={`${baseClasses} bg-red-100 text-red-800`}>Rejected</span>;
    default:
      return <span className={`${baseClasses} bg-gray-200 text-gray-700`}>{status}</span>;
  }
};

const TranscriptsPage = () => {
  const [interviews, setInterviews] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const limit = 10;
  const navigate = useNavigate();
  const { setSelectedInterview } = useTranscript();

  const fetchInterviews = async (pageNum = 1) => {
    try {
      const res = await authenticatedFetch(`/api/interviews?page=${pageNum}&limit=${limit}`);
      if (!res.ok) throw new Error("Failed to fetch interviews");
      const data = await res.json();
      setInterviews(data.interviews);
      setTotal(data.total);
      setPage(data.page);
    } catch (err) {
      setInterviews([]);
      setTotal(0);
    }
  };

  useEffect(() => {
    fetchInterviews(page);
    // eslint-disable-next-line
  }, [page]);

  const getTranscriptPreview = (transcript) => {
    if (!transcript) return "";
    const text = typeof transcript === 'string' ? transcript : JSON.stringify(transcript);
    return text.length > 40 ? text.slice(0, 40) + "..." : text;
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div>
            <CandidateNavbar />
    <div className="p-4 md:p-8 bg-white ">
      <div className="flex justify-between items-center border-b mb-6 overflow-x-auto">
        <h2 className="text-xl md:text-2xl font-semibold">Transcripts</h2>
      </div>
      <div className="w-full flex justify-center items-center">
        <div className="w-full max-w-6xl bg-gradient-to-r from-blue-100 via-purple-100 to-purple-200 rounded-2xl shadow-lg p-2 md:p-6">
          <div className="hidden md:block w-full overflow-x-auto">
            <table className="min-w-full table-auto border rounded-lg overflow-hidden shadow-sm text-sm relative">
              <thead className="bg-gray-50 text-gray-600 sticky top-0 z-10">
                <tr>
                  <th className="px-6 py-3 text-left">Position Name</th>
                  <th className="px-6 py-3 text-left">Summary</th>
                  <th className="px-6 py-3 text-left">Transcript</th>
                  <th className="px-6 py-3 text-left">Review Status</th>
                  <th className="px-6 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody>
                {interviews.map((app, index) => (
                  <tr key={index} className="border-t hover:bg-gray-50 transition-colors duration-200">
                    <td className="px-6 py-4 font-medium">{app.positionName}</td>
                    <td className="px-6 py-4">{app.positionDescription}</td>
                    <td className="px-6 py-4">{getTranscriptPreview(app.transcript)}</td>
                    <td className="px-6 py-4">{getReviewStatusBadge(app.reviewStatus)}</td>
                    <td className="px-6 py-4">
                      <button 
                        className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-medium px-4 py-2 rounded-lg shadow-md hover:shadow-lg transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2" 
                        onClick={() => { setSelectedInterview(app); navigate('/transcript-details'); }}
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {/* Pagination removed as requested */}
          </div>
          <div className="md:hidden space-y-4">
            {interviews.map((app, index) => (
              <div key={index} className="border rounded-lg p-4 shadow-sm bg-white hover:shadow-md transition-shadow duration-200">
                <div className="text-base font-semibold mb-1">{app.positionName}</div>
                <div className="text-sm text-gray-600 mb-1">Summary: {app.positionDescription}</div>
                <div className="text-sm text-gray-500 mb-2">Transcript: {getTranscriptPreview(app.transcript)}</div>
                <div className="mb-2">Review Status: {getReviewStatusBadge(app.reviewStatus)}</div>
                <button 
                  className="w-full text-center mt-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-medium px-4 py-2 rounded-lg shadow-md hover:shadow-lg transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2" 
                  onClick={() => { setSelectedInterview(app); navigate('/transcript-details'); }}
                >
                  View Details
                </button>
              </div>
            ))}
            {/* Pagination removed as requested */}
          </div>
        </div>
      </div>
    </div>
    </div>

  );
};

export default TranscriptsPage; 