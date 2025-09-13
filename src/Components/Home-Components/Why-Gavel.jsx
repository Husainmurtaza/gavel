import { FaPhoneAlt } from "react-icons/fa";
import { FaClock, FaRobot, FaBalanceScale, FaDatabase, FaChartLine, FaPlug } from "react-icons/fa";

const features = [
  {
    icon: <FaClock className="text-blue-500 text-xl" />,
    title: "Save Time",
    points: [
      "Automated interview scheduling",
      "24/7 candidate screening",
      "Instant evaluation reports"
    ],
    description: "Conduct hundreds of initial phone screenings simultaneously, reducing the time spent on manual interviews by up to 85%."
  },
  {
    icon: <FaRobot className="text-blue-500 text-xl" />,
    title: "AI Intelligence",
    points: [
      "Natural conversation flow",
      "Skill-based assessment",
      "Personality insights"
    ],
    description: "Our advanced natural language processing evaluates technical skills, communication abilities, and cultural fit with unmatched accuracy."
  },
  {
    icon: <FaBalanceScale className="text-blue-500 text-xl" />,
    title: "Reduce Bias",
    points: [
      "Consistent candidate experience",
      "Skills-first evaluation",
      "Bias-free algorithms"
    ],
    description: "Eliminate unconscious bias from your hiring process with standardized interviews and objective skill assessment."
  },
  {
    icon: <FaDatabase className="text-blue-500 text-xl" />,
    title: "Centralized Data",
    points: [
      "Searchable candidate database",
      "Interview transcriptions",
      "Secure cloud storage"
    ],
    description: "Keep all candidate information, interview recordings, and evaluations in one secure location for easy reference."
  },
  {
    icon: <FaChartLine className="text-blue-500 text-xl" />,
    title: "Actionable Insights",
    points: [
      "Hiring funnel metrics",
      "Skill gap analysis",
      "Customizable reports"
    ],
    description: "Gain valuable insights into your recruitment process and candidate pool with detailed analytics."
  },
  {
    icon: <FaPlug className="text-blue-500 text-xl" />,
    title: "Easy Integration",
    points: [
      "API connections",
      "Data synchronization",
      "Custom workflows"
    ],
    description: "Seamlessly integrate with popular ATS and HRIS systems to maintain your existing workflow."
  }
];

const  WhyGavel = () => {
  return (
    <section className="px-4 py-16 md:px-12 lg:px-24 bg-white text-center">
      <div className="max-w-3xl mx-auto mb-12">
        <h2 className="text-2xl sm:text-3xl font-semibold text-gray-900 mb-4">Try the Voice Recruiter Demo</h2>
        <p className="text-gray-600 mb-8">
          Experience how our AI conducts phone interviews and evaluates responses in real-time.
        </p>
        <div className="bg-white w-fullborder border-gray-200 rounded-md px-6 py-4 shadow-sm"style=
        {
          {
            display: "flex",
            justifyContent: "center",
            padding: "20px",
          }
        }>
          <button className="bg-blue-600 text-white px-6 py-3 rounded-md flex items-center gap-2 hover:bg-blue-700 transition cursor-pointer">
            <FaPhoneAlt /> Start Call
          </button>
        </div>
      </div>

      <div className="mb-12">
        <h3 className="text-2xl sm:text-3xl font-semibold text-gray-900 mb-4">Why Choose Gavel?</h3>
        <p className="text-gray-600 max-w-2xl mx-auto">
          Our AI-powered voice recruitment platform helps you identify the best talent efficiently and objectively.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {features.map((feature, idx) => (
          <div key={idx} className="bg-white p-6 rounded-lg shadow-sm hover:shadow-md transition text-left">
            <div className="bg-blue-100 w-12 h-12 flex items-center justify-center rounded-full mb-4">
              {feature.icon}
            </div>
            <h4 className="text-lg font-semibold text-gray-900 mb-2">{feature.title}</h4>
            <p className="text-gray-600 mb-4">{feature.description}</p>
            <ul className="text-sm text-gray-700 space-y-1 list-disc list-inside">
              {feature.points.map((point, i) => (
                <li key={i} className="text-black font-medium">{point}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
};

export default WhyGavel;
