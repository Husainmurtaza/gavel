import Plan from '../Components/Pricing-Components/Plan';  
import FAQ from '../Components/Pricing-Components/FAQ';
import Section from '../Components/Pricing-Components/Section';
import MainNavbar from '../Header-Footer/Header';
  
const Pricing = () => {
  return (
    <div>
      <MainNavbar />
      <Plan /> 
      <FAQ/>
      <Section/>
    </div>
  );
};

export default Pricing;