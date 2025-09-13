import React from 'react';
import { PhoneCall, Mail, MessageSquare } from 'lucide-react';

const ContactSection = () => {
  const contactMethods = [
    {
      icon: PhoneCall,
      title: "Phone Support",
      description: "Available Monday-Friday<br />9am-5pm ET",
      buttonText: "+1 (888) 555-1234"
    },
    {
      icon: Mail,
      title: "Email Support",
      description: "We typically respond<br />within 24 hours",
      buttonText: "support@gavelapp.com"
    },
    {
      icon: MessageSquare,
      title: "Live Chat",
      description: "Available 24/7 for<br />immediate assistance",
      buttonText: "Start Chat"
    }
  ];

  return (
    <section className="py-16 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-2xl md:text-3xl font-bold mb-8 text-center text-gray-900">
            Still Need Help?
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {contactMethods.map((method, index) => {
              const Icon = method.icon;
              return (
                <div 
                  key={index}
                  className="border border-gray-100 bg-white hover:shadow-md transition-all duration-200 rounded-lg"
                >
                  <div className="p-6 flex flex-col items-center text-center">
                    <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                      <Icon className="h-6 w-6 text-blue-600" />
                    </div>
                    <h3 className="text-lg font-bold mb-2 text-gray-900">
                      {method.title}
                    </h3>
                    <p 
                      className="text-gray-600 mb-4" 
                      dangerouslySetInnerHTML={{ __html: method.description }}
                    />
                    <button className="px-4 py-2 border border-blue-600 text-blue-600 rounded-md hover:bg-blue-50 transition-colors cursor-pointer">
                      {method.buttonText}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
};

export default ContactSection;