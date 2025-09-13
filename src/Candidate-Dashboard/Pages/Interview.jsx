import PositionSelectSection from "../Interview-Components/Hero";
import InterviewTabs from "../Interview-Components/Interview";
import CandidateNavbar from "../Header-Footer/Header";
import React, { useState } from "react";

const Interview = () => {
  const [selectedPosition, setSelectedPosition] = useState("");
  return (
    <div>
      <CandidateNavbar />
      <PositionSelectSection selectedPosition={selectedPosition} setSelectedPosition={setSelectedPosition} />
      <InterviewTabs selectedPosition={selectedPosition} />
    </div>
  );
};

export default Interview;

