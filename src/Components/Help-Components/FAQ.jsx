import React from 'react';


const FAQSection = () => {
  const faqs = [
    {
      id: "getting-started",
      question: "How does Gavel's AI interview technology work?",
      answer: "Gavel uses advanced natural language processing and voice AI to conduct phone interviews with candidates. The system asks questions, understands responses, and dynamically adapts the conversation flow. It then analyzes the responses to provide hiring teams with comprehensive insights on candidate fit."
    },
    {
      question: "How do I set up my first AI interview?",
      answer: "Setting up an interview is simple. First, create a job position and define the key skills and qualifications. Next, customize your interview questions or use our pre-built templates. Finally, add candidate contact information, and our system will automatically schedule and conduct the interviews."
    },
    {
      question: "Can I customize the questions for different roles?",
      answer: "Yes, Gavel allows you to fully customize interview questions for each position. You can create specific questions to assess technical skills, soft skills, experience, and cultural fit. You can also use our extensive library of pre-built questions tailored to various industries and roles."
    },
    {
      question: "How secure is candidate data on your platform?",
      answer: "Gavel takes data security very seriously. We employ industry-standard encryption, secure data storage, and strict access controls. We are GDPR compliant and never sell or share candidate data with third parties. All data is anonymized for internal system improvements."
    },
    {
      question: "Can Gavel integrate with my existing ATS or HRIS?",
      answer: "Yes, Gavel offers integrations with popular ATS systems like Greenhouse, Lever, Workday, and more. Our API also allows for custom integrations with other HR systems. Contact our support team for details about specific integrations for your organization."
    },
    {
      id: "troubleshooting",
      question: "What should I do if candidates report technical issues?",
      answer: "If candidates experience technical difficulties, they can use the support link provided in their interview invitation. For urgent issues, contact our support team directly. We recommend candidates use a quiet environment with a stable internet connection and updated browser for optimal experience."
    }
  ];

  return (
    <section id="getting-started" className="py-16 bg-white scroll-mt-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-2xl md:text-3xl font-bold mb-8 text-gray-900">
            Frequently Asked Questions
          </h2>
          
          <div className="space-y-6">
            {faqs.map((faq, index) => (
              <div 
                key={index}
                id={faq.id}
                className={`border border-gray-100 rounded-lg p-6 shadow-sm ${faq.id ? 'scroll-mt-24' : ''}`}
              >
                <h3 className="text-lg md:text-xl font-bold mb-2 text-gray-900">
                  {faq.question}
                </h3>
                <p className="text-gray-700">
                  {faq.answer}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default FAQSection;