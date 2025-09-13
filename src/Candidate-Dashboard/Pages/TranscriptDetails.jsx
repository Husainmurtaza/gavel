import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranscript } from './TranscriptContext';
import CandidateNavbar from '../Header-Footer/Header';

const getReviewStatusBadge = (status) => {
  const baseClasses = "px-4 py-2 rounded-full text-sm font-semibold whitespace-nowrap shadow-sm";
  switch (status) {
    case 'pending':
      return <span className={`${baseClasses} bg-yellow-100 text-yellow-800 border border-yellow-200`}>⏳ Pending Review</span>;
    case 'approved':
      return <span className={`${baseClasses} bg-green-100 text-green-800 border border-green-200`}>✅ Approved</span>;
    case 'rejected':
      return <span className={`${baseClasses} bg-red-100 text-red-800 border border-red-200`}>❌ Rejected</span>;
    default:
      return <span className={`${baseClasses} bg-gray-100 text-gray-700 border border-gray-200`}>{status}</span>;
  }
};

const TranscriptDetails = () => {
  const navigate = useNavigate();
  const { selectedInterview: interview } = useTranscript();

  if (!interview) {
    return (
      <div>
        <CandidateNavbar />
        <div className="w-full min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 py-8 px-4 flex flex-col items-center justify-center">
          <div className="bg-white p-8 rounded-2xl shadow-xl text-center max-w-md w-full">
            <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <span className="text-red-600 text-2xl">⚠️</span>
            </div>
            <div className="text-red-600 text-lg mb-4 font-medium">No transcript selected</div>
            <p className="text-gray-600 mb-6">Please go back and select a transcript to view its details.</p>
            <button 
              className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-lg hover:shadow-lg transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2" 
              onClick={() => navigate(-1)}
            >
              ← Back to Transcripts
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <CandidateNavbar />
      <div className="w-full min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 py-8 px-4">
        <div className="w-full max-w-6xl mx-auto">
          {/* Back Button */}
          <button 
            className="mb-8 px-6 py-3 bg-white text-gray-700 rounded-xl hover:bg-gray-50 hover:shadow-md transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 border border-gray-200 flex items-center gap-2" 
            onClick={() => navigate(-1)}
          >
            <span className="text-lg">←</span>
            <span className="font-medium">Back to Transcripts</span>
          </button>

          {/* Header Section */}
          <div className="bg-white rounded-2xl shadow-lg p-8 mb-8 border border-gray-100">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">
              <div className="flex-1">
                <h1 className="text-3xl lg:text-4xl font-bold text-gray-900 mb-3">
                  {interview.positionName}
                </h1>
                <p className="text-lg text-gray-600 mb-4 leading-relaxed">
                  {interview.positionDescription}
                </p>
                <div className="flex items-center gap-4 text-sm text-gray-500">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                    <span>Candidate Email: <span className="font-medium text-gray-700">{interview.email}</span></span>
                  </div>
                </div>
              </div>
              <div className="flex-shrink-0">
                {getReviewStatusBadge(interview.reviewStatus)}
              </div>
            </div>
          </div>

          {/* Summary Section */}
          <div className="bg-white rounded-2xl shadow-lg p-8 mb-8 border border-gray-100">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                <span className="text-blue-600 text-xl">📋</span>
              </div>
              <h2 className="text-2xl font-bold text-gray-900">Interview Summary</h2>
            </div>
            <div className="bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-100 rounded-xl p-6">
              <div className="text-gray-800 leading-relaxed text-lg">
                {typeof interview.summary === 'string' ? interview.summary : JSON.stringify(interview.summary, null, 2)}
              </div>
            </div>
          </div>

          {/* Transcript Section */}
          <div className="bg-white rounded-2xl shadow-lg p-8 border border-gray-100">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center">
                <span className="text-purple-600 text-xl">🎤</span>
              </div>
              <h2 className="text-2xl font-bold text-gray-900">Full Transcript</h2>
            </div>
            <div className="bg-gray-50 border border-gray-200 rounded-xl p-6 max-h-[70vh] overflow-y-auto">
              <div className="text-gray-800 leading-relaxed text-lg whitespace-pre-wrap">
                {typeof interview.transcript === 'string' ? interview.transcript : JSON.stringify(interview.transcript, null, 2)}
              </div>
            </div>
            <div className="mt-4 text-sm text-gray-500 text-center">
              Scroll to view the complete interview transcript
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TranscriptDetails; 