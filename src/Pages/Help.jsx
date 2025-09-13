import  Hero from "../Components/Help-Components/Hero";
import Quick from "../Components/Help-Components/Quick";
import FAQ from "../Components/Help-Components/FAQ";
import Guidance from "../Components/Help-Components/Guidance";
import Contact from "../Components/Help-Components/Contact"
import MainNavbar from "../Header-Footer/Header";

const Help = () => {
  return (
    <div>
      <MainNavbar />
      <Hero />
      <Quick/>
      <FAQ/>
      <Guidance/>
      <Contact/>
    </div>
  );
};


export default Help;