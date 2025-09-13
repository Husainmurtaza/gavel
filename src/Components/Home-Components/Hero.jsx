import { FaPhoneAlt } from "react-icons/fa";
import { BsLightningChargeFill } from "react-icons/bs";
import { FaUserTie } from "react-icons/fa";

const HeroSection = () => {
  return (
    <section className="bg-white text-center px-4 py-16 md:px-12 lg:px-24">
      <h1 className="text-4xl sm:text-5xl font-bold text-gray-900 mb-4">
        Revolutionize Your <span className="text-blue-600">Recruitment</span> Process
      </h1>
      <p className="text-gray-600 text-lg max-w-2xl mx-auto mb-8">
        Gavel uses advanced AI to conduct interviews, automatically screen candidates,
        and provide insightful evaluations.
      </p>
      <div className="flex flex-col sm:flex-row justify-center items-center gap-4 mb-16">
        <button className="bg-blue-600 text-white px-6 py-3 rounded-md flex items-center gap-2 hover:bg-blue-700 transition cursor-pointer">
          <FaPhoneAlt /> Start Interview
        </button>
        <button className="border border-gray-300 px-6 py-3 rounded-md flex items-center gap-2 hover:bg-gray-100 transition cursor-pointer">
          ⚡ See Demo
        </button>
      </div>

      <div className="grid gap-6 grid-cols-1 md:grid-cols-3">
        {/* Card 1 */}
        <div className="bg-white p-20 rounded-lg shadow-lg hover:shadow-md transition">
          <div className="bg-blue-100 w-12 h-12 flex items-center justify-center rounded-full mx-auto mb-4">
            <FaPhoneAlt className="text-blue-500 text-xl" />
          </div>
          <h3 className="font-semibold text-lg text-gray-900 mb-2">AI Phone Screening</h3>
          <p className="text-gray-600">
            Automated phone interviews that feel natural and gather key candidate insights.
          </p>
        </div>
        {/* Card 2 */}
        <div className="bg-white p-20 rounded-lg shadow-lg hover:shadow-md transition">
          <div className="bg-blue-100 w-12 h-12 flex items-center justify-center rounded-full mx-auto mb-4">
            <BsLightningChargeFill className="text-blue-500 text-xl" />
          </div>
          <h3 className="font-semibold text-lg text-gray-900 mb-2">Lightning Fast</h3>
          <p className="text-gray-600">
            Screen hundreds of candidates simultaneously, reducing time-to-hire by 70%.
          </p>
        </div>
        {/* Card 3 */}
        <div className="bg-white p-20 rounded-lg shadow-lg hover:shadow-md transition">
          <div className="bg-blue-100 w-12 h-12 flex items-center justify-center rounded-full mx-auto mb-4">
            <FaUserTie className="text-blue-500 text-xl" />
          </div>
          <h3 className="font-semibold text-lg text-gray-900 mb-2">Qualified Candidates</h3>
          <p className="text-gray-600">
            AI-powered evaluation to ensure only the most qualified candidates advance.
          </p>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
