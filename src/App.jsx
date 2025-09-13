import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Home from './Pages/Home';
import About from './Pages/About';
import Help from './Pages/Help';
import Pricing from './Pages/Pricing';
import Candidate from './Candidate-Dashboard/Pages/Candidate';
import LoginForm from './Components/Signup-Login Component/Login';
import SignupForm from './Components/Signup-Login Component/Signup';
import Interview from './Candidate-Dashboard/Pages/Interview';
import AdminDashboard from './Admin-Dashboard/pages/Home';
import { useEffect, useState } from 'react';
import Positions from './Admin-Dashboard/components/Positions';
import Clients from './Admin-Dashboard/components/Clients';
import Candidates from './Admin-Dashboard/components/Candidates';
import Dashboard from './Client-to-dashboard/Page/DashBoard';
import TranscriptsPage from './Candidate-Dashboard/Pages/Transcripts';
import TranscriptDetails from './Candidate-Dashboard/Pages/TranscriptDetails';
import { TranscriptProvider } from './Candidate-Dashboard/Pages/TranscriptContext';
import AdminTranscripts from './Admin-Dashboard/components/Transcripts';
import Companies from './Admin-Dashboard/components/Companies';
import Profile from './Admin-Dashboard/pages/Profile';
import ClientProfile from './Client-to-dashboard/Page/ClientProfile';
import CandidateProfile from './Candidate-Dashboard/Pages/CandidateProfile';
import { authenticatedFetch } from './utils/api';
import Contact from './Components/Contact';

const App = () => {
  return (
    <TranscriptProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Home/>} />
          <Route path="/about" element={<About />} />
          <Route path="/interview" element={<Interview />} />
          <Route path="/pricing" element={<Pricing />} />
          <Route path='/help' element={<Help/>}/>
          <Route path='/login' element={<LoginForm/>}/>
          <Route path='/signup' element={<SignupForm/>}/>
          <Route path='/contact' element={<Contact/>}/>


          <Route path='/candidate' element={<Candidate/>}/>
          <Route path='/transcripts' element={<TranscriptsPage/>}/>
          <Route path='/transcript-details' element={<TranscriptDetails/>}/>
          <Route path='/dashboard' element={<Dashboard/>}/>
          <Route path='/client-profile' element={<ClientProfile/>}/>
          <Route path='/candidate-profile' element={<CandidateProfile/>}/>




           <Route path='/admin'  element={<AdminDashboard/>}/>
           <Route path='/admin/positions' element={<Positions/>} />
           <Route path='/admin/clients' element={<Clients/>} />
           <Route path='/admin/candidates' element={<Candidates />} />
           <Route path='/admin/transcripts' element={<AdminTranscripts/>}/>
           <Route path='/admin/companies' element={<Companies/>} />
           <Route path='/admin/profile' element={<Profile />} />
        </Routes>
      </Router>
    </TranscriptProvider>
  );
};   

// Private route for admin
function PrivateAdminRoute({ children }) {
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    async function checkAdmin() {
      const adminFlag = localStorage.getItem('admin_logged_in');
      if (!adminFlag) {
        setIsAuthenticated(false);
        setLoading(false);
        return;
      }
      try {
        const res = await authenticatedFetch('/api/protected/admin');
        setIsAuthenticated(res.ok);
      } catch {
        setIsAuthenticated(false);
      }
      setLoading(false);
    }
    checkAdmin();
  }, []);

  if (loading) return null;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

export default App;