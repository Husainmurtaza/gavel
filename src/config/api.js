// API Configuration - Always use live backend with HTTPS
const API_BASE_URL = 'https://evolvegov.com';



// Export the API_BASE_URL for use in other files
export { API_BASE_URL };

// API Endpoints
export const API_ENDPOINTS = {
  // Auth endpoints
  LOGIN_ADMIN: `${API_BASE_URL}/api/login/admin`,
  LOGIN_CLIENT: `${API_BASE_URL}/api/login/client`,
  LOGIN_CANDIDATE: `${API_BASE_URL}/api/login/candidate`,
  SIGNUP_CLIENT: `${API_BASE_URL}/api/signup/client`,
  SIGNUP_CANDIDATE: `${API_BASE_URL}/api/signup/candidate`,
  LOGOUT: `${API_BASE_URL}/api/logout`,
  
  // Protected routes
  PROTECTED_ADMIN: `${API_BASE_URL}/api/protected/admin`,
  PROTECTED_CLIENT: `${API_BASE_URL}/api/protected/client`,
  PROTECTED_CANDIDATE: `${API_BASE_URL}/api/protected/candidate`,
  
  // Profile endpoints
  ADMIN_PROFILE: `${API_BASE_URL}/api/admin/profile`,
  CLIENT_PROFILE: `${API_BASE_URL}/api/clients/profile`,
  CANDIDATE_PROFILE: `${API_BASE_URL}/api/candidates/profile`,
  CLIENT_ENSURE_ROLE: `${API_BASE_URL}/api/clients/ensure-role`,

  
  // Admin CRUD endpoints
  POSITIONS: `${API_BASE_URL}/api/positions`,
  COMPANIES: `${API_BASE_URL}/api/companies`,
  CLIENTS: `${API_BASE_URL}/api/clients`,
  CANDIDATES: `${API_BASE_URL}/api/candidates`,
  ADMIN_INTERVIEWS: `${API_BASE_URL}/api/admin/interviews`,
  
  // Interview endpoints
  INTERVIEWS: `${API_BASE_URL}/api/interviews`,
  INTERVIEWS_CHECK: `${API_BASE_URL}/api/interviews/check`,
  CLIENT_INTERVIEWS: `${API_BASE_URL}/api/client/interviews`,
  
  // Webhook URL (external service)
  WEBHOOK_URL: "https://n8n.srv846726.hstgr.cloud/webhook/81e6dbf4-f379-4015-9dfd-bc46f137286b",
  
  // External API (for reports)
  VAPI_REPORT: "https://gavel.noshaiautomation.com/vapi-report.php"
};

export default API_ENDPOINTS;
