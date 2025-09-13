import { Link } from "react-router-dom";
import { Gavel, HelpCircle, FileText } from "lucide-react";

const QuickLinksSection = () => {
  const quickLinks = [
    {
      to: "#getting-started",
      icon: Gavel,
      title: "Getting Started",
      description: "Learn the basics of setting up and using Gavel"
    },
    {
      to: "#troubleshooting",
      icon: HelpCircle,
      title: "Troubleshooting",
      description: "Solutions to common issues and technical problems"
    },
    {
      to: "#guides",
      icon: FileText,
      title: "Guides & Tutorials",
      description: "Step-by-step guides to maximize your Gavel experience"
    }
  ];

  return (
    <section className=" bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-2xl md:text-3xl font-bold mb-8 text-center text-gray-900">
          Quick Links
        </h2>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {quickLinks.map((link, index) => (
            <Link to={link.to} key={index} className="no-underline">
              <div className="border border-gray-100 hover:border-blue-600 transition-all duration-200 shadow-sm hover:shadow-md bg-white h-full rounded-lg">
                <div className="p-8 flex flex-col items-center text-center">
                  <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                    <link.icon className="h-6 w-6 text-blue-600" />
                  </div>
                  <h3 className="text-xl font-bold mb-2 text-gray-900">{link.title}</h3>
                  <p className="text-gray-600">{link.description}</p>
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
};

export default QuickLinksSection;