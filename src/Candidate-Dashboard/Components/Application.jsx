import React, { useEffect, useState } from 'react';
import { authenticatedFetch } from '../../utils/api';

const getReviewStatusBadge = (status) => {
  const baseClasses = `
    inline-block
    px-3 py-1
    rounded-full
    text-xs font-semibold
    whitespace-nowrap
    shadow-sm
    transition-all
    duration-200
    ease-in-out
    bg-gradient-to-r
  `;

  switch (status) {
    case 'pending':
      return <span className={`${baseClasses} from-yellow-200 to-yellow-400 text-yellow-900`}>Pending</span>;
    case 'approved':
      return <span className={`${baseClasses} from-green-200 to-green-400 text-green-900`}>Approved</span>;
    case 'rejected':
      return <span className={`${baseClasses} from-red-200 to-red-400 text-red-900`}>Rejected</span>;
    default:
      return <span className={`${baseClasses} from-gray-200 to-gray-300 text-gray-700`}>{status}</span>;
  }
};


const ApplicationsTable = () => {
  const [interviews, setInterviews] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const limit = 10;

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
    <div className="p-4 md:p-8 bg-white rounded-lg shadow-md">
      {/* Tabs Header */}
      <div className="flex justify-between items-center border-b border-gray-200 mb-6">
        
        <button
          className="mt-[-15px] px-5 py-1.5 bg-gradient-to-r from-blue-500 to-purple-500 text-white text-sm font-bold rounded-lg shadow-md hover:from-blue-600 hover:to-purple-600 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-1 active:scale-95 transition-all duration-200 ease-in-out cursor-pointer "
        >
          View All
        </button>
      </div>

      {/* Heading */}
      <div className="text-center mb-6">
        <h2 className="text-2xl md:text-3xl font-extrabold tracking-tight text-gray-800">
          Your Applications
        </h2>
        <div className="w-40 h-0.5 bg-blue-600 mx-auto mt-1 rounded-full" />
      </div>


      {/* Responsive table on md+, cards on mobile */}

      {/* Desktop Table View */}
      <div className="hidden md:block">
        <div className="overflow-x-auto rounded-lg shadow-sm border border-gray-200">
          <table className="min-w-full table-auto text-sm text-left text-gray-700">
            <thead className="bg-gradient-to-r from-blue-500 to-purple-500 text-white uppercase text-xs tracking-wider">
              <tr>
                <th className="px-6 py-3">Position Name</th>
                <th className="px-6 py-3">Description</th>
                <th className="px-6 py-3">Transcript</th>
                <th className="px-6 py-3">Review Status</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {interviews.map((app, index) => (
                <tr key={index} className={
                  `transition ${index % 2 === 0 ? 'bg-gradient-to-r from-blue-50 to-purple-50' : 'bg-white'} hover:bg-gradient-to-r hover:from-blue-100 hover:to-purple-100`}
                >
                  <td className="px-6 py-4 font-medium text-gray-900">{app.positionName}</td>
                  <td className="px-6 py-4">{app.positionDescription}</td>
                  <td className="px-6 py-4">{getTranscriptPreview(app.transcript)}</td>
                  <td className="px-6 py-4">{getReviewStatusBadge(app.reviewStatus)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex justify-end items-center mt-6 gap-3">
          
        </div>
      </div>
      {/* Mobile Card View */}
      <div className="md:hidden space-y-4">
        {interviews.map((app, index) => (
          <div key={index} className="border-2 rounded-lg p-4 shadow-sm bg-white" style={{ borderImage: 'linear-gradient(to right, #3b82f6, #a78bfa) 1' }}>
            <div className="text-base font-semibold text-gray-900 mb-1">{app.positionName}</div>
            <div className="text-sm text-gray-600 mb-1">{app.positionDescription}</div>
            <div className="text-sm text-gray-500 mb-2">Transcript: {getTranscriptPreview(app.transcript)}</div>
            <div className="text-sm">Review Status: {getReviewStatusBadge(app.reviewStatus)}</div>
          </div>
        ))}

        {/* Pagination */}
        <div className="flex justify-between items-center mt-4">
          
        </div>
      </div>
    </div>
  );
};

export default ApplicationsTable;
