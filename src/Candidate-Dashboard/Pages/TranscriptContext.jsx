import { createContext, useContext, useState, useEffect } from "react";

const TranscriptContext = createContext();

export const useTranscript = () => useContext(TranscriptContext);

export const TranscriptProvider = ({ children }) => {
  const [selectedInterview, setSelectedInterviewState] = useState(() => {
    const stored = localStorage.getItem('selectedInterview');
    return stored ? JSON.parse(stored) : null;
  });

  useEffect(() => {
    if (selectedInterview) {
      localStorage.setItem('selectedInterview', JSON.stringify(selectedInterview));
    } else {
      localStorage.removeItem('selectedInterview');
    }
  }, [selectedInterview]);

  const setSelectedInterview = (interview) => {
    setSelectedInterviewState(interview);
  };

  return (
    <TranscriptContext.Provider value={{ selectedInterview, setSelectedInterview }}>
      {children}
    </TranscriptContext.Provider>
  );
}; 