import React, { useEffect, useState } from "react";
import { authenticatedFetch } from "../../utils/api";

const PositionSelectSection = ({ selectedPosition, setSelectedPosition }) => {
  const [positions, setPositions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchPositions = async () => {
      try {
        const res = await authenticatedFetch("/api/positions");
        if (!res.ok) throw new Error("Failed to fetch positions");
        const data = await res.json();
        setPositions(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchPositions();
  }, []);

  return (
    <section className="w-full px-2 py-10 flex justify-center items-center bg-white">
      <div className="w-full max-w-2xl bg-gradient-to-r from-blue-100 via-purple-100 to-purple-200 rounded-2xl shadow-lg p-6 md:p-10 mx-auto text-center">
        <h2 className="text-3xl md:text-4xl font-bold text-blue-700 mb-4">
          Legal Position Interview
        </h2>
        <p className="text-gray-700 mb-6">
          What position do you want to apply for?
        </p>
        {loading ? (
          <p>Loading positions...</p>
        ) : error ? (
          <p className="text-red-600">{error}</p>
        ) : (
          <div className="w-full flex justify-center">
            <div className="w-full max-w-xs p-[2px] bg-gradient-to-r from-blue-400 to-purple-500 rounded-md shadow">
              <div className="relative">
                <select
                  className="w-full px-4 py-2 bg-white text-gray-800 font-semibold rounded-md focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-2 appearance-none shadow-inner"
                  value={selectedPosition || ""}
                  onChange={e => setSelectedPosition(e.target.value)}
                >
                  <option value="" disabled>Select a position</option>
                  {positions.map(pos => (
                    <option key={pos._id || pos.id} value={pos._id || pos.id}>{pos.name}</option>
                  ))}
                </select>
                <span className="pointer-events-none absolute right-3 top-1/2 transform -translate-y-1/2 text-purple-500 text-lg">
                  ▼
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};

export default PositionSelectSection;
