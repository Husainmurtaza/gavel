import React from 'react';

const GuidesResourcesSection = () => {
  const resources = [
    {
      title: "Getting Started Guide",
      description: "A complete walkthrough of setting up your Gavel account and first interview.",
      buttonText: "Read Guide"
    },
    {
      title: "Integration Tutorials",
      description: "Step-by-step instructions for connecting Gavel with your existing systems.",
      buttonText: "View Tutorials"
    },
    {
      title: "Best Practices",
      description: "Tips for creating effective interview questions and evaluating results.",
      buttonText: "Learn More"
    },
    {
      title: "Video Tutorials",
      description: "Watch our tutorial videos for visual guidance on using Gavel features.",
      buttonText: "Watch Videos"
    }
  ];

  return (
    <section id="guides" className="py-16 bg-gray-50 scroll-mt-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-2xl md:text-3xl font-bold mb-8 text-gray-900">
            Guides & Resources
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {resources.map((resource, index) => (
              <div 
                key={index}
                className="border border-gray-100 bg-white hover:shadow-md transition-all duration-200 rounded-lg"
              >
                <div className="p-6">
                  <h3 className="text-xl font-bold mb-2 text-gray-900">
                    {resource.title}
                  </h3>
                  <p className="text-gray-600 mb-4">
                    {resource.description}
                  </p>
                  <button className="px-4 py-2 border border-blue-600 text-blue-600 rounded-md hover:bg-blue-50 transition-colors cursor-pointer">
                    {resource.buttonText}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default GuidesResourcesSection;