import React from 'react';
import { HelpCircle } from 'lucide-react';

const CTASection = () => {
  return (
    <section className="py-16 bg-[#5656f0] text-white">
      <div className="gavel-container">
        <div className="max-w-4xl mx-auto flex flex-col md:flex-row items-center justify-between gap-8">
          {/* Text Content */}
          <div className="text-center md:text-left">
            <h2 className="text-2xl md:text-3xl font-bold mb-4 font-helvetica">
              Still have questions?
            </h2>
            <p className="text-white/90 max-w-md">
              Our team is here to help you find the perfect plan for your organization's needs.
            </p>
          </div>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4">
            <button
              type="button"
              className="px-6 py-3 text-lg font-medium bg-black text-gavel-blue rounded-md cursor-pointer"
            >
              Contact Sales
            </button>
            <button
              type="button"
              className="px-6 py-3 text-lg font-medium bg-transparent border border-white text-white rounded-md hover:bg-white/10 flex items-center justify-center transition duration-200 cursor-pointer"
            >
              <HelpCircle className="h-4 w-4 mr-2" />
              Schedule a Demo
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CTASection;
