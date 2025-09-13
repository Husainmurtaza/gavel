import React, { useState, useRef, useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Vapi from "@vapi-ai/web";
import { toast, ToastContainer } from 'react-toastify';
import { authenticatedFetch } from "../../utils/api";
import 'react-toastify/dist/ReactToastify.css';

const WEBHOOK_URL = "https://n8n.srv846726.hstgr.cloud/webhook/81e6dbf4-f379-4015-9dfd-bc46f137286b";
const VAPI_PUBLIC_KEY = "aef3ff40-74b1-4134-b13e-28f6b7e05fe3";

const InterviewTabs = ({ selectedPosition }) => {
  const [activeTab, setActiveTab] = useState("interview");
  const [loading, setLoading] = useState(false);
  const [interviewActive, setInterviewActive] = useState(false);
  const [interviewCompleted, setInterviewCompleted] = useState(false);
  const [positions, setPositions] = useState([]);
  const vapiRef = useRef(null);

  useEffect(() => {
    // Fetch positions for id lookup
    const fetchPositions = async () => {
      try {
        const res = await authenticatedFetch("/api/positions");
        if (!res.ok) throw new Error("Could not fetch positions");
        const data = await res.json();
        setPositions(data);
      } catch (err) {
        // Optionally handle error
      }
    };
    fetchPositions();
  }, []);

  const tabContentVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.3 } },
    exit: { opacity: 0, y: -10, transition: { duration: 0.2 } },
  };

  const handleBeginInterview = async () => {
    if (!selectedPosition) {
      toast.error("Please select a position to apply for");
      return;
    }
    setLoading(true);
    try {
      // Get candidate info
      const res = await authenticatedFetch("/api/protected/candidate");
      if (!res.ok) throw new Error("Session expired or not logged in");
      const { id, email, firstName } = await res.json();
      // Check if already applied for this position
      const checkRes = await authenticatedFetch(`/api/interviews/check?candidateId=${id}&positionId=${selectedPosition}`);
      const checkData = await checkRes.json();
      if (checkData.applied) {
        toast.error("You can't apply for the same job again");
        setLoading(false);
        return;
      }
      // Find selected position by id
      const found = positions.find(pos => (pos._id || pos.id) === selectedPosition);
      if (!found) {
        toast.error("Selected position not found. Please refresh and try again.");
        setLoading(false);
        return;
      }
      const positionId = found._id || found.id;
      const positionName = found.name;
      const positionDescription = found.projectDescription || "";
      const companyName = found.companyName || "";
      const webhookRes = await fetch(WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, email, firstName, positionId, positionName, positionDescription, companyName })
      });
      // Fix: Only parse JSON if response has content
      let webhookResponseJson = null;
      const text = await webhookRes.text();
      if (text) {
        try {
          webhookResponseJson = JSON.parse(text);
        } catch (e) {
          console.warn('Webhook response is not valid JSON:', text);
        }
      }
      console.log('Webhook response (for Vapi):', webhookResponseJson);
      if (!webhookResponseJson) {
        toast.error("Interview setup failed. Please try again.");
        setLoading(false);
        return;
      }
      if (!webhookRes.ok) throw new Error("Failed to notify webhook");
      if (!vapiRef.current) {
        vapiRef.current = new Vapi(VAPI_PUBLIC_KEY);
        vapiRef.current.on('error', (error) => {
          console.error('Vapi error:', error, JSON.stringify(error, null, 2));
          if (error && typeof error === 'object') {
            for (const key in error) {
              console.log(`Vapi error detail [${key}]:`, error[key]);
            }
          }
        });
      }
      vapiRef.current.start(webhookResponseJson);
      setInterviewActive(true);
      setInterviewCompleted(false);
      toast.success("Interview started successfully!");
    } catch (err) {
      toast.error("Could not start interview: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleStopInterview = async () => {
    if (vapiRef.current) {
      vapiRef.current.stop();
      setInterviewActive(false);
      setInterviewCompleted(true);
      toast.success("Interview completed successfully!");

      try {
        const response = await fetch("https://gavel.noshaiautomation.com/vapi-report.php");
        const rawText = await response.text();
        console.log("🟡 Raw log string from server:", rawText);

        // Find the last JSON object in the response (handles multiple lines)
        const jsonMatches = rawText.match(/\{[\s\S]*?\}/g);
        if (jsonMatches && jsonMatches.length > 0) {
          const lastJson = jsonMatches[jsonMatches.length - 1];
          try {
            const report = JSON.parse(lastJson);
            console.log("✅ Parsed Report Object:", report);
            if (report.summary) console.log("📄 Summary:", report.summary);
            if (report.transcript) console.log("📝 Transcript:", report.transcript);
          } catch (parseErr) {
            console.warn("⚠️ Failed to parse JSON from response.", parseErr);
          }
        } else {
          console.warn("⚠️ No JSON found in response.");
        }
      } catch (err) {
        console.error("❌ Error fetching/parsing report:", err);
      }
    }
  };
  
  

  return (
    <div className="w-full px-4 py-10 flex justify-center items-start bg-white">
      <ToastContainer position="top-right" autoClose={3000} />
      <div className="w-full max-w-2xl">
        {/* Tabs */}
        <div className="flex rounded-md overflow-hidden mb-8 shadow-sm ">
          <button
            onClick={() => setActiveTab("interview")}
            className={`flex-1 py-2 text-sm md:text-base font-medium transition-colors cursor-pointer ${
              activeTab === "interview"
                ? "bg-white text-black"
                : "bg-gray-100 text-gray-600"
            }`}
          >
            Interview
          </button>
          <button
            onClick={() => setActiveTab("instructions")}
            className={`flex-1 py-2 text-sm md:text-base font-medium transition-colors cursor-pointer ${
              activeTab === "instructions"
                ? "bg-white text-black"
                : "bg-gray-100 text-gray-600"
            }`}
          >
            Instructions
          </button>
        </div>

        {/* Tab Content */}
        <div className="bg-gradient-to-r from-blue-100 via-purple-100 to-purple-200 rounded-2xl shadow-lg p-1">
          <div className="bg-white rounded-xl p-6 md:p-10 text-center">
            <AnimatePresence mode="wait">
              {activeTab === "interview" ? (
                <motion.div
                  key="interview"
                  variants={tabContentVariants}
                  initial="hidden"
                  animate="visible"
                  exit="exit"
                >
                  <h2 className="text-lg md:text-xl font-medium mb-4">
                    Ready to start your interview?
                  </h2>
                  
                  <button
                    className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-5 rounded-md text-sm cursor-pointer disabled:opacity-60 transition-all duration-200"
                    onClick={handleBeginInterview}
                    disabled={loading || interviewActive}
                  >
                    {loading ? (
                      <span className="flex items-center gap-2">
                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        Interview Starting...
                      </span>
                    ) : interviewActive ? (
                      <span className="flex items-center gap-2">
                        <div className="w-2 h-2 bg-white rounded-full animate-pulse"></div>
                        Interview in Progress
                      </span>
                    ) : (
                      "Begin Interview"
                    )}
                  </button>
                  {interviewActive && (
                    <button
                      className="ml-4 bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-5 rounded-md text-sm cursor-pointer transition-all duration-200"
                      onClick={handleStopInterview}
                    >
                      Complete Interview
                    </button>
                  )}
                  
                  {/* Interview Status Messages */}
                  {interviewActive && (
                    <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                      <p className="text-blue-800 text-sm font-medium">
                        🎤 Interview is now active. Please speak clearly and answer the questions.
                      </p>
                    </div>
                  )}
                  
                  {/* Completion Message */}
                  {interviewCompleted && (
                    <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-lg">
                      <div className="flex items-start gap-3">
                        <div className="flex-shrink-0 w-6 h-6 bg-green-100 rounded-full flex items-center justify-center">
                          <span className="text-green-600 text-sm">✓</span>
                        </div>
                        <div className="text-left">
                          <p className="text-green-800 text-sm font-medium mb-2">
                            Interview completed successfully!
                          </p>
                          <p className="text-green-700 text-xs mb-2">
                            Your interview has been recorded and will be reviewed by our team. 
                            Please check the Transcripts page for further instructions and status updates.
                          </p>
                          <p className="text-green-600 text-xs font-medium">
                            You'll be notified once the review is complete.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </motion.div>
              ) : (
                <motion.div
                  key="instructions"
                  variants={tabContentVariants}
                  initial="hidden"
                  animate="visible"
                  exit="exit"
                >
                  <h2 className="text-lg md:text-xl font-semibold text-blue-600 mb-4">
                    How the Interview Works
                  </h2>
                  <div className="text-left text-sm text-gray-800 space-y-2">
                    <p>
                      <strong className="text-blue-600">1. Microphone Access:</strong>{" "}
                      When prompted, allow the application access to your microphone.
                    </p>
                    <p>
                      <strong className="text-blue-600">2. AI Introduction:</strong>{" "}
                      Gavel AI will introduce itself and begin the interview process using voice.
                    </p>
                    <p>
                      <strong className="text-blue-600">3. Answering Questions:</strong>{" "}
                      Click the microphone button to begin speaking. Click it again when you've finished your response.
                    </p>
                    <p>
                      <strong className="text-blue-600">4. Follow-up Questions:</strong>{" "}
                      The AI will ask follow-up questions based on your responses to gather comprehensive information.
                    </p>
                    <p>
                      <strong className="text-blue-600">5. Interview Completion:</strong>{" "}
                      After all questions are answered, the AI will conclude the interview and provide next steps.
                    </p>
                  </div>

                  <div className="mt-6 bg-blue-50 text-sm text-blue-700 p-4 rounded-md">
                    <p className="font-semibold text-center mb-2">Technical Requirements:</p>
                    <ul className="list-disc list-inside space-y-1 text-left">
                      <li>A working microphone</li>
                      <li>A quiet environment for clear audio capture</li>
                      <li>Using Chrome, Firefox, or Edge for optimal compatibility</li>
                      <li>Stable internet connection</li>
                    </ul>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
};

export default InterviewTabs;
