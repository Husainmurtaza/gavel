import React from "react";

const FAQItem = ({ question, answer }) => (
  <div className="bg-white p-6 rounded-lg border border-gray-100 shadow-sm">
    <h3 className="text-xl font-bold mb-3 text-gray-900">
      {question}
    </h3>
    <p className="text-gray-600">{answer}</p>
  </div>
);

const FAQSection = () => {
  const faqs = [
    {
      question: "What counts as an interview?",
      answer: "Any completed AI phone conversation with a candidate counts as one interview. There's no time limit per interview."
    },
    {
      question: "Can I change plans at any time?",
      answer: "Yes, you can upgrade or downgrade your plan at any time. Changes will be reflected in your next billing cycle."
    },
    {
      question: "What happens if I exceed my interview limit?",
      answer: "You can purchase additional interviews as needed at a per-interview rate, or upgrade to the next tier for better value."
    },
    {
      question: "Do you offer discounts for annual billing?",
      answer: "Yes, you can save 20% by choosing annual billing on any of our paid plans. Contact our sales team for details."
    },
    {
      question: "What kind of support is included?",
      answer: "All plans include email support. Professional plans receive priority email support, while Enterprise clients get 24/7 support and a dedicated account manager."
    },
    {
      question: "Do you offer custom plans?",
      answer: "Yes, we can create custom plans for organizations with specific needs. Contact our sales team to discuss your requirements."
    }
  ];

  return (
    <section className="py-16 bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-6 text-gray-900">
              Frequently Asked Questions
            </h2>
            <p className="text-lg text-gray-600">
              Find answers to common questions about our pricing plans
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {faqs.map((faq, index) => (
              <FAQItem 
                key={index}
                question={faq.question}
                answer={faq.answer}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default FAQSection;