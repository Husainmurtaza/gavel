import AboutSection from "../Components/About-Components/Hero";
import TeamSection from "../Components/About-Components/Team";
import ValuesSection from "../Components/About-Components/Values";
import MainNavbar from "../Header-Footer/Header";

const About = () => {
  return (
    <div>
        <MainNavbar />
        <AboutSection />
        <TeamSection />
        <ValuesSection />
    </div>
  );
};

export default About;

