import HeroSection from "../Components/Home-Components/Hero";
import TestimonialSection from "../Components/Home-Components/Testimonials";
import WhyGavel from "../Components/Home-Components/Why-Gavel";
import MainNavbar from "../Header-Footer/Header";

const Home = () => {
  return (
    <div>
    <MainNavbar />
    <div>
      <HeroSection />
      <WhyGavel />
      <TestimonialSection />
    </div>
    </div>
  );
};

export default Home;

