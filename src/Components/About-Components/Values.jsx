import React from "react";
import { FaTrophy, FaBalanceScale, FaBullseye, FaUsers } from "react-icons/fa";
import { GiArtificialHive } from "react-icons/gi";

const values = [
  {
    title: "Excellence",
    description:
      "We're committed to building products that exceed expectations and deliver exceptional results for our customers.",
    icon: <FaTrophy className="text-xl" />,
  },
  {
    title: "Fairness",
    description:
      "We design our technology to eliminate bias and create equal opportunities for all candidates.",
    icon: <FaBalanceScale className="text-xl" />,
  },
  {
    title: "Innovation",
    description:
      "We continuously push the boundaries of what's possible with AI technology in the recruitment space.",
    icon: <FaBullseye className="text-xl" />,
  },
  {
    title: "Collaboration",
    description:
      "We believe in the power of teamwork and partnership to solve complex problems.",
    icon: <FaUsers className="text-xl" />,
  },
];

const ValuesSection = () => {
  return (
    <div>
      <section className="bg-white py-16 px-4 text-center">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">Our Values</h2>
        <p className="text-gray-600 max-w-2xl mx-auto mb-12">
          The principles that guide our work and define our company culture
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-y-10 gap-x-8 max-w-5xl mx-auto">
          {values.map((val, idx) => (
            <div key={idx} className="flex items-start space-x-4 text-left">
              <div className="bg-blue-100 text-blue-600 p-3 rounded-full">
                {val.icon}
              </div>
              <div>
                <h3 className="font-semibold text-lg mb-1">{val.title}</h3>
                <p className="text-gray-600 text-sm">{val.description}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="bg-gradient-to-r from-blue-500 to-blue-600 text-white py-16 text-center px-4">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">
          Join Us in Redefining Recruitment
        </h2>
        <p className="mb-8 max-w-xl mx-auto">
          Experience how our AI-powered platform can transform your hiring process.
        </p>
        <button className="bg-white text-blue-600 font-semibold py-2 px-6 rounded-md shadow-md hover:bg-blue-100 cursor-pointer">
          Get Started
        </button>
      </section>
    </div>
  );
};

export default ValuesSection;