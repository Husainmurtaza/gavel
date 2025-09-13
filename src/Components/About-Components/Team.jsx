import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import Slider from "react-slick";
import Nick from "../../assets/Nick.jpeg";
import Liza from "../../assets/Liza.jpeg";    
const leadershipData = [
  {
    name: "Nick Lysett",
    title: "CEO & Co-Founder",
    description:
      "Former head of talent acquisition with 15+ years of experience in the recruitment industry.",
    image: Nick, // Replace with actual path to image
  },
  {
    name: "Liza Yakimchuk",
    title: "COO & Co-Founder",
    description:
      "AI researcher and engineer with expertise in natural language processing and machine learning.",
    image: Liza, // Replace with actual path to image
  },
];

const TeamSection = () => {
  const settings = {
    dots: true,
    infinite: true,
    speed: 500,
    slidesToShow: 2,
    slidesToScroll: 1,
    responsive: [
      {
        breakpoint: 768,
        settings: {
          slidesToShow: 1,
        },
      },
    ],
  };

  return (
    <section className="py-12 px-4 max-w-7xl mx-auto text-center">
      <h2 className="text-3xl md:text-4xl font-bold mb-2">Our Leadership</h2>
      <p className="text-gray-600 mb-10">
        Meet the team that's changing how companies hire talent
      </p>
    <Slider {...settings}>
  {leadershipData.map((leader, index) => (
    <div key={index} className="flex justify-center">
      <div className="p-6 flex flex-col items-center text-center">
        <img
          src={leader.image}
          alt={leader.name}
          className="w-40 h-40 rounded-full object-cover mb-4"
        />
        <h3 className="text-xl font-semibold mb-1">{leader.name}</h3>
        <p className="text-blue-600 text-sm font-medium mb-2">
          {leader.title}
        </p>
        <p className="text-gray-600 text-sm max-w-xs mx-auto">
          {leader.description}
        </p>
      </div>
    </div>
  ))}
</Slider>

    </section>
  );
};

export default TeamSection;
