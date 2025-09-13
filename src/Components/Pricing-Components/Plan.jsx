import React from "react";
import { Check } from "lucide-react";

const Card = ({ className, children }) => (
  <div className={`rounded-2xl border p-6 bg-white ${className}`}>{children}</div>
);

const CardHeader = ({ className, children }) => (
  <div className={`mb-4 ${className}`}>{children}</div>
);

const CardContent = ({ className, children }) => (
  <div className={`mb-6 ${className}`}>{children}</div>
);

const CardFooter = ({ className, children }) => (
  <div className={className}>{children}</div>
);

const Button = ({ variant = "default", className, children }) => {
  const baseStyles = "py-2 px-4 rounded-lg font-medium text-center transition-all w-full focus:outline-none focus:ring-2 focus:ring-gavel-blue focus:ring-offset-2";
  const variants = {
    default: "border border-blue text-white bg-[#5656f0] hover:bg-black hover:text-white cursor-pointer",
    outline: "border border-blue text-blue bg-white hover:bg-black hover:text-white cursor-pointer",
  };
  return (
    <button className={`${baseStyles} ${variants[variant]} ${className || ""}`.trim()}>
      {children}
    </button>
  );
};

const PricingTier = ({
  title,
  price,
  description,
  features,
  buttonText,
  buttonVariant = "default",
  popular = false,
}) => {
  const showDollarSign =
    typeof price === "number" || (!isNaN(Number(price)) && price !== "Free Trial" && price !== "Contact Sales");

  return (
    <Card className={`relative flex flex-col h-full ${popular ? 'border-gavel-blue shadow-md' : 'border-gray-100'}`}>
      {popular && (
        <div className="absolute top-0 right-0 -translate-y-1/2 translate-x-0">
          <span className="inline-block bg-gavel-blue text-white text-xs font-bold py-1 px-3 rounded-full">
            Most Popular
          </span>
        </div>
      )}
      <CardHeader>
        <h3 className="text-2xl font-bold font-helvetica">{title}</h3>
        <div className="mt-2 mb-1">
          <span className="text-3xl font-bold">
            {showDollarSign ? `$${price}` : price}
          </span>
          {showDollarSign && <span className="text-gray-500 ml-1">/month</span>}
        </div>
        <p className="text-gray-600">{description}</p>
      </CardHeader>
      <CardContent className="flex-grow">
        <ul className="space-y-3">
          {Array.isArray(features) &&
            features.map((feature, index) => (
              <li key={index} className="flex items-start">
                <Check className="h-5 w-5 text-green-500 mr-2 flex-shrink-0 mt-0.5" />
                <span className="text-gray-700">{feature}</span>
              </li>
            ))}
        </ul>
      </CardContent>
      <CardFooter>
        <Button variant={buttonVariant} className="w-full">
          {buttonText}
        </Button>
      </CardFooter>
    </Card>
  );
};

const pricingTiers = [
  {
    title: "Starter",
    price: "Free Trial",
    description: "Perfect for trying out Gavel",
    features: [
      "Up to 5 AI phone interviews per month",
      "Basic candidate assessment",
      "Interview recordings",
      "Email support",
    ],
    buttonText: "Start Free Trial",
    buttonVariant: "outline",
    popular: false,
  },
  {
    title: "Professional",
    price: 9999,
    description: "Ideal for growing teams",
    features: [
      "Up to 150 AI phone interviews per month",
      "Advanced candidate scoring",
      "Interview recordings & transcriptions",
      "Custom interview questions",
      "Priority email support",
    ],
    buttonText: "Start Free Trial",
    popular: true,
  },
  {
    title: "Enterprise",
    price: "Contact Sales",
    description: "For high-volume recruitment",
    features: [
      "Unlimited AI phone interviews",
      "Advanced analytics dashboard",
      "Multiple ATS integrations",
      "Custom AI voice personas",
      "Team collaboration tools",
      "API access",
      "Dedicated account manager",
      "24/7 priority support",
    ],
    buttonText: "Contact Sales",
    buttonVariant: "outline",
    popular: false,
  },
];

const Pricing = () => {
  return (
    <div className="min-h-screen flex flex-col bg-white">
      {/* Hero Section */}
      <section className="py-16 md:py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="max-w-3xl mx-auto text-center">
            <h1 className="text-4xl md:text-5xl font-bold mb-6">
              <span className="text-gray-900">Transparent </span>
              <span className="text-gavel-blue">Pricing</span>
              <span className="text-gray-900"> Plans</span>
            </h1>
            <p className="text-lg md:text-xl text-gray-600 mb-4">
              Choose the perfect plan for your recruitment needs
            </p>
            <p className="text-gray-500 mb-0">
              All plans include a 14-day free trial — no credit card required
            </p>
          </div>
        </div>
      </section>

      {/* Pricing Tiers */}
      <section className="py-8 pb-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {pricingTiers.map((tier, idx) => (
              <PricingTier key={tier.title} {...tier} />
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

export default Pricing;