import { FaPhoneAlt } from "react-icons/fa";
import { BsLightningChargeFill } from "react-icons/bs";
import { FaUserTie } from "react-icons/fa";

export default function AboutSection() {
  return (
    <section className="text-center px-4 py-12">
      {/* About Section */}
      <div className="max-w-4xl mx-auto mb-16">
        <h2 className="text-5xl font-bold mb-2"  style={
        {
            paddingBlock: "20px",
        }
      }>
          About <span className="text-blue-600">Gavel</span>
        </h2>
        <p className="text-gray-600 text-2xl mb-6"  style={
        {
            paddingBlock: "5px",
        }
      }>
          Transforming the recruitment landscape with advanced AI technology
        </p>
        <div className="bg-gray-50 p-6 rounded-xl text-gray-700 text-base shadow-sm">
          <p className="mb-4 font-medium">
            Founded in 2023, Gavel is revolutionizing the hiring process with our AI-powered
            voice recruitment platform. We're on a mission to help companies identify top talent
            efficiently and objectively, while providing candidates with a seamless interview experience.
          </p>
          <p className="font-medium">
            Our team of AI experts, recruitment specialists, and software engineers have created a
            platform that conducts natural-sounding phone interviews, evaluates responses with
            exceptional accuracy, and delivers actionable insights to hiring teams.
          </p>
        </div>
      </div>

      {/* Mission Section */}
      <div className="bg-gray-50 py-12">
        <h3 className="text-2xl font-bold mb-2">Our Mission</h3>
        <p className="text-gray-600 text-lg mb-10 max-w-2xl mx-auto">
          We're building a future where the hiring process is faster, fairer, and more effective for everyone involved.
        </p>

      <div className="grid gap-6 grid-cols-1 md:grid-cols-3">
        {/* Card 1 */}
        <div className="bg-white p-20 rounded-lg shadow-lg hover:shadow-md transition">
          <div className="bg-blue-100 w-12 h-12 flex items-center justify-center rounded-full mx-auto mb-4">
            <FaPhoneAlt className="text-blue-500 text-xl" />
          </div>
          <h3 className="font-semibold text-2xl text-gray-900 mb-2">AI Phone Screening</h3>
          <p className="text-gray-600">
            Automated phone interviews that feel natural and gather key candidate insights.
          </p>
        </div>
        {/* Card 2 */}
        <div className="bg-white p-20 rounded-lg shadow-lg hover:shadow-md transition">
          <div className="bg-blue-100 w-12 h-12 flex items-center justify-center rounded-full mx-auto mb-4">
            <BsLightningChargeFill className="text-blue-500 text-xl" />
          </div>
          <h3 className="font-semibold text-2xl text-gray-900 mb-2">Lightning Fast</h3>
          <p className="text-gray-600">
            Screen hundreds of candidates simultaneously, reducing time-to-hire by 70%.
          </p>
        </div>
        {/* Card 3 */}
        <div className="bg-white p-20 rounded-lg shadow-lg hover:shadow-md transition">
          <div className="bg-blue-100 w-12 h-12 flex items-center justify-center rounded-full mx-auto mb-4">
            <FaUserTie className="text-blue-500 text-xl" />
          </div>
          <h3 className="font-semibold text-2xl text-gray-900 mb-2">Qualified Candidates</h3>
          <p className="text-gray-600">
            AI-powered evaluation to ensure only the most qualified candidates advance.
          </p>
        </div>
      </div>
      </div>
    </section>
  );
}
