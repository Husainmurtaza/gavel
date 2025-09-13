import React from 'react';

const testimonials = [
  {
    stars: 5,
    quote:
      'Gavel has completely transformed our technical hiring process. We\'ve reduced our time-to-hire by 60% while improving the quality of our engineering candidates.',
    name: 'Sarah Johnson',
    title: 'HR Director, TechNova Inc.',
  },
  {
    stars: 4,
    quote:
      'The AI phone screening is remarkably natural. Candidates have given us positive feedback, saying they couldn\'t tell they were talking to an AI recruiter.',
    name: 'Michael Chen',
    title: 'Talent Acquisition Manager, Quantum Solutions',
  },
  {
    stars: 5,
    quote:
      'Gavel\'s analytics have given us unprecedented insights into our hiring funnel. We\'ve identified bottlenecks and improved our process from top to bottom.',
    name: 'Emily Rodriguez',
    title: 'Head of Recruiting, Global Finance Group',
  },
];

export default function TestimonialSection() {
  return (
    <section className="bg-white text-center py-16 px-4">
      {/* Section Header */}
      <div className="max-w-4xl mx-auto mb-12">
        <h2 className="text-3xl font-bold mb-2">What Our Customers Say</h2>
        <p className="text-gray-600">
          Companies of all sizes are revolutionizing their recruitment process with VoiceScout.
        </p>
      </div>

      {/* Testimonials */}
      <div className="grid md:grid-cols-3 gap-6 max-w-6xl mx-auto">
        {testimonials.map((item, index) => (
          <div
            key={index}
            className="bg-white border rounded-lg p-6 shadow-sm hover:shadow-md transition duration-300"
          >
            {/* Stars */}
            <div className="flex justify-center mb-4 text-yellow-400">
              {'★'.repeat(item.stars)}
              {'☆'.repeat(5 - item.stars)}
            </div>
            {/* Quote */}
            <p className="italic text-gray-700 mb-6">"{item.quote}"</p>
            {/* Name */}
            <p className="font-bold">{item.name}</p>
            <p className="text-sm text-gray-500">{item.title}</p>
          </div>
        ))}
      </div>

      {/* CTA Section */}
      <div className="bg-gradient-to-r from-blue-500 to-blue-700 text-white mt-20 py-16 px-6 rounded-lg shadow-lg">
        <h3 className="text-2xl font-bold mb-4">
          Ready to Transform Your Recruitment Process?
        </h3>
        <p className="mb-6 max-w-xl mx-auto">
          Join hundreds of companies saving time and finding better candidates with Gavel's AI-powered voice recruitment.
        </p>
        <button className="bg-white text-blue-600 font-semibold px-6 py-3 rounded hover:bg-blue-100 transition cursor-pointer">
          Get Started
        </button>
      </div>
    </section>
  );
}
