import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Backend URL configuration
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'https://zero1-classroom-1.onrender.com';
const API = `${BACKEND_URL}/api`.replace(/\/+/g, '/'); // Remove double slashes

// Add axios interceptors for better error handling
axios.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('Axios error:', {
      config: error.config,
      response: error.response,
      message: error.message
    });
    
    // If response is undefined, it means network error
    if (!error.response) {
      console.error('Network error - no response received');
      return Promise.reject(new Error('Network error - cannot connect to server'));
    }
    
    return Promise.reject(error);
  }
);

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    if (token && userData) {
      try {
        setUser(JSON.parse(userData));
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      } catch (error) {
        console.error('Error parsing user data:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    try {
      console.log('Attempting login to:', `${API}/login`);
      
      const response = await axios.post(`${API}/login`, { username, password });
      
      console.log('Login response:', response);
      
      if (!response.data) {
        throw new Error('No data received from server');
      }
      
      const { access_token, user: userData } = response.data;
      
      if (!access_token || !userData) {
        throw new Error('Invalid response format');
      }
      
      localStorage.setItem('token', access_token);
      localStorage.setItem('user', JSON.stringify(userData));
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      return { success: true };
    } catch (error) {
      console.error('Login error details:', {
        message: error.message,
        response: error.response,
        status: error.response?.status,
        data: error.response?.data
      });
      
      if (error.response?.status === 404) {
        return { success: false, error: 'API endpoint not found. Please check backend URL.' };
      }
      
      if (error.response?.status === 0) {
        return { success: false, error: 'Cannot connect to server. Please check if backend is running.' };
      }
      
      return { 
        success: false, 
        error: error.response?.data?.detail || error.message || 'Login failed' 
      };
    }
  };

  const register = async (username, email, password) => {
    try {
      console.log('Attempting registration to:', `${API}/register`);
      
      const response = await axios.post(`${API}/register`, { username, email, password });
      
      console.log('Register response:', response);
      
      if (!response.data) {
        throw new Error('No data received from server');
      }
      
      const { access_token, user: userData } = response.data;
      
      if (!access_token || !userData) {
        throw new Error('Invalid response format');
      }
      
      localStorage.setItem('token', access_token);
      localStorage.setItem('user', JSON.stringify(userData));
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      return { success: true };
    } catch (error) {
      console.error('Register error details:', {
        message: error.message,
        response: error.response,
        status: error.response?.status,
        data: error.response?.data
      });
      
      if (error.response?.status === 404) {
        return { success: false, error: 'API endpoint not found. Please check backend URL.' };
      }
      
      if (error.response?.status === 0) {
        return { success: false, error: 'Cannot connect to server. Please check if backend is running.' };
      }
      
      return { 
        success: false, 
        error: error.response?.data?.detail || error.message || 'Registration failed' 
      };
    }
  };

  const logout = async () => {
    try {
      await axios.post(`${API}/logout`);
    } catch (error) {
      console.error('Logout error:', error);
    }
    
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Backend Test Component
const BackendTest = () => {
  const [status, setStatus] = useState('Testing...');
  const [error, setError] = useState(null);

  useEffect(() => {
    const testBackend = async () => {
      try {
        console.log('Testing backend URL:', BACKEND_URL);
        const response = await axios.get(BACKEND_URL);
        console.log('Backend test response:', response);
        setStatus('Backend is running!');
      } catch (error) {
        console.error('Backend test error:', error);
        setError(error.message);
        setStatus('Backend test failed');
      }
    };

    testBackend();
  }, []);

  return (
    <div style={{ padding: '10px', margin: '10px', border: '1px solid #ccc', backgroundColor: 'white' }}>
      <h3>Backend Status: {status}</h3>
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      <p>Backend URL: {BACKEND_URL}</p>
      <p>API URL: {API}</p>
    </div>
  );
};

// Login Component
const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const result = await login(username, password);
    if (result.success) {
      navigate('/');
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 to-blue-100 flex items-center justify-center p-4">
      {/* Backend Test Component */}
      <BackendTest />
      
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex flex-row items-center justify-center gap-3 mb-2">
            <img src={process.env.PUBLIC_URL + '/Untitled_design__2_-removebg-preview.png'} alt="Classroom Logo" style={{ width: 56, height: 56 }} />
            <span className="text-3xl font-bold text-gray-900">Classroom</span>
          </div>
          <p className="text-gray-600">Sign in to your Classroom account</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              placeholder="Enter your username"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              placeholder="Enter your password"
              required
            />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-indigo-700 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors disabled:opacity-50"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-gray-600">
            Don't have an account?{' '}
            <button
              onClick={() => navigate('/register')}
              className="text-indigo-600 hover:text-indigo-700 font-medium"
            >
              Sign up
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

// Register Component
const Register = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const result = await register(username, email, password);
    if (result.success) {
      navigate('/');
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex flex-row items-center justify-center gap-3 mb-2">
            <img src={process.env.PUBLIC_URL + '/Untitled_design__2_-removebg-preview.png'} alt="Classroom Logo" style={{ width: 56, height: 56 }} />
            <span className="text-3xl font-bold text-gray-900">Classroom</span>
          </div>
          <div className="text-gray-500 mb-2">Create Account</div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              placeholder="Choose a username"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              placeholder="Enter your email"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              placeholder="Create a password"
              required
            />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-indigo-700 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors disabled:opacity-50"
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-gray-600">
            Already have an account?{' '}
            <button
              onClick={() => navigate('/login')}
              className="text-indigo-600 hover:text-indigo-700 font-medium"
            >
              Sign in
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }
  
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

// Dashboard Component
const Dashboard = () => {
  const { user } = useAuth();
  
  if (user.role === 'student') {
    return <StudentDashboard />;
  } else if (user.role === 'professor') {
    return <ProfessorDashboard />;
  } else if (user.role === 'moderator') {
    return <ModeratorDashboard />;
  }
  
  return <Navigate to="/login" replace />;
};

// Main App Component
function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route 
            path="/" 
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } 
          />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;