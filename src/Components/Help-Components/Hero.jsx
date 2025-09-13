import { Search } from "lucide-react";

const HelpHeroSection = () => {
  return (
    <div className=" flex flex-col bg-white">
      {/* Hero Section */}
      <section className=" md:py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="max-w-3xl mx-auto text-center">
            <h1 className="text-4xl md:text-5xl font-bold mb-6">
              <span className="text-gray-900">How Can We </span>
              <span className="text-blue-600">Help?</span>
            </h1>
            <p className="text-lg md:text-xl text-gray-600 mb-8">
              Find answers to common questions or contact our support team
            </p>
            
            <div className="flex items-center max-w-xl mx-auto">
              <div className="relative flex-grow">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input 
                  type="text" 
                  placeholder="Search for help..." 
                  className="pl-10 pr-4 py-2 w-full rounded-l-md border border-gray-300 focus-visible:ring-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-600" 
                />
              </div>
              <button className="h-full px-4 py-2 bg-blue-600 text-white rounded-r-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-600 cursor-pointer">
                Search
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default HelpHeroSection;