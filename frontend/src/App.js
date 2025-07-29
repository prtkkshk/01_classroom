import React, { useState, useEffect, createContext, useContext, Component } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Backend URL configuration
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'https://zero1-classroom-1.onrender.com';
// Ensure proper URL formatting by removing trailing slash from BACKEND_URL and adding /api
const cleanBackendUrl = BACKEND_URL.replace(/\/$/, ''); // Remove trailing slash
const API = `${cleanBackendUrl}/api`;



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
    
    // Check if both token and userData exist and are not "undefined" strings
    if (token && userData && userData !== 'undefined' && userData !== 'null') {
      try {
        const parsedUser = JSON.parse(userData);
        if (parsedUser && typeof parsedUser === 'object') {
          setUser(parsedUser);
          axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        } else {
          throw new Error('Invalid user data format');
        }
      } catch (error) {
        console.error('Error parsing user data:', error);
        // Clean up invalid data
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }
    } else {
      // Clean up any invalid data
      if (!token) localStorage.removeItem('user');
      if (!userData || userData === 'undefined' || userData === 'null') {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    try {
      const response = await axios.post(`${API}/login`, { username, password });
      
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
      // Handle network errors
      if (!error.response) {
        return { success: false, error: 'Network error - cannot connect to server. Please check your internet connection.' };
      }
      
      if (error.response?.status === 404) {
        return { success: false, error: 'API endpoint not found. Please check backend URL.' };
      }
      
      if (error.response?.status === 0) {
        return { success: false, error: 'Cannot connect to server. Please check if backend is running.' };
      }
      
      // Handle specific HTTP status codes
      if (error.response?.status === 401) {
        return { success: false, error: 'Invalid username or password.' };
      }
      
      if (error.response?.status === 422) {
        return { success: false, error: 'Invalid input data. Please check your credentials.' };
      }
      
      if (error.response?.status >= 500) {
        return { success: false, error: 'Server error. Please try again later.' };
      }
      
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data?.message || error.message || 'Login failed' 
      };
    }
  };

  const register = async (username, email, password) => {
    try {
      const response = await axios.post(`${API}/register`, { username, email, password });
      
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
      // Handle network errors
      if (!error.response) {
        return { success: false, error: 'Network error - cannot connect to server. Please check your internet connection.' };
      }
      
      if (error.response?.status === 404) {
        return { success: false, error: 'API endpoint not found. Please check backend URL.' };
      }
      
      if (error.response?.status === 0) {
        return { success: false, error: 'Cannot connect to server. Please check if backend is running.' };
      }
      
      // Handle specific HTTP status codes
      if (error.response?.status === 409) {
        return { success: false, error: 'Username or email already exists. Please choose different credentials.' };
      }
      
      if (error.response?.status === 422) {
        return { success: false, error: 'Invalid input data. Please check your information.' };
      }
      
      if (error.response?.status >= 500) {
        return { success: false, error: 'Server error. Please try again later.' };
      }
      
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data?.message || error.message || 'Registration failed' 
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

// Error Boundary Component
class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full text-center">
            <h1 className="text-2xl font-bold text-red-600 mb-4">Something went wrong</h1>
            <p className="text-gray-600 mb-4">We're sorry, but something unexpected happened.</p>
            <button
              onClick={() => window.location.reload()}
              className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}



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

    // Basic validation
    if (!username.trim()) {
      setError('Username is required');
      setLoading(false);
      return;
    }

    if (!password.trim()) {
      setError('Password is required');
      setLoading(false);
      return;
    }

    const result = await login(username.trim(), password);
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
            <img 
              src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
              alt="Classroom Logo" 
              style={{ width: 56, height: 56 }} 
              onError={(e) => {
                e.target.style.display = 'none';
                console.error('Logo image failed to load');
              }}
            />
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
    
    // Input validation
    if (!username.trim()) {
      setError('Username is required');
      return;
    }
    
    if (!email.trim()) {
      setError('Email is required');
      return;
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      setError('Please enter a valid email address');
      return;
    }
    
    if (!password.trim()) {
      setError('Password is required');
      return;
    }
    
    if (password.length < 6) {
      setError('Password must be at least 6 characters long');
      return;
    }
    
    setLoading(true);
    setError('');

    const result = await register(username.trim(), email.trim(), password);
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
            <img 
              src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
              alt="Classroom Logo" 
              style={{ width: 56, height: 56 }} 
              onError={(e) => {
                e.target.style.display = 'none';
                console.error('Logo image failed to load');
              }}
            />
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

// Student Dashboard Component
const StudentDashboard = () => {
  const { user, logout } = useAuth();
  const [courses, setCourses] = useState([]);
  const [joinCode, setJoinCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchCourses();
  }, []);

  const fetchCourses = async () => {
    try {
      const response = await axios.get(`${API}/courses`);
      setCourses(response.data);
    } catch (error) {
      console.error('Error fetching courses:', error);
    }
  };

  const handleJoinCourse = async (e) => {
    e.preventDefault();
    if (!joinCode.trim()) {
      setError('Please enter a course code');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.post(`${API}/courses/join`, { code: joinCode.trim() });
      setSuccess('Successfully joined the course!');
      setJoinCode('');
      fetchCourses(); // Refresh the courses list
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to join course');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gray-900">Student Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Welcome, {user.username}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0 space-y-6">
          {/* Join Course Section */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-medium text-gray-900 mb-4">Join a Course</h2>
            <form onSubmit={handleJoinCourse} className="flex gap-4">
              <input
                type="text"
                value={joinCode}
                onChange={(e) => setJoinCode(e.target.value.toUpperCase())}
                placeholder="Enter 8-letter course code"
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                maxLength={8}
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
              >
                {loading ? 'Joining...' : 'Join Course'}
              </button>
            </form>
            {error && (
              <p className="text-red-600 text-sm mt-2">{error}</p>
            )}
            {success && (
              <p className="text-green-600 text-sm mt-2">{success}</p>
            )}
          </div>

          {/* Enrolled Courses */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-medium text-gray-900 mb-4">Your Classes</h2>
            {courses.length === 0 ? (
              <p className="text-gray-600">No classes enrolled yet. Join a course using the code above.</p>
            ) : (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {courses.map((course) => (
                  <div key={course.id} className="border border-gray-200 rounded-lg p-4">
                    <h3 className="font-medium text-gray-900">{course.name}</h3>
                    <p className="text-sm text-gray-600">Code: {course.code}</p>
                    <p className="text-sm text-gray-600">Professor: {course.professor_name}</p>
                    <p className="text-sm text-gray-600">Students: {course.students.length}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const ProfessorDashboard = () => {
  const { user, logout } = useAuth();
  const [courses, setCourses] = useState([]);
  const [newCourseName, setNewCourseName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchCourses();
  }, []);

  const fetchCourses = async () => {
    try {
      const response = await axios.get(`${API}/courses`);
      setCourses(response.data);
    } catch (error) {
      console.error('Error fetching courses:', error);
    }
  };

  const handleCreateCourse = async (e) => {
    e.preventDefault();
    if (!newCourseName.trim()) {
      setError('Please enter a course name');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const response = await axios.post(`${API}/courses`, { name: newCourseName.trim() });
      setSuccess(`Course "${response.data.name}" created successfully! Code: ${response.data.code}`);
      setNewCourseName('');
      fetchCourses(); // Refresh the courses list
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to create course');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteCourse = async (courseId) => {
    if (!window.confirm('Are you sure you want to delete this course? This action cannot be undone.')) {
      return;
    }

    try {
      await axios.delete(`${API}/courses/${courseId}`);
      setSuccess('Course deleted successfully!');
      fetchCourses(); // Refresh the courses list
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to delete course');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gray-900">Professor Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Welcome, Prof. {user.username}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0 space-y-6">
          {/* Create Course Section */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-medium text-gray-900 mb-4">Create a New Course</h2>
            <form onSubmit={handleCreateCourse} className="flex gap-4">
              <input
                type="text"
                value={newCourseName}
                onChange={(e) => setNewCourseName(e.target.value)}
                placeholder="Enter course name"
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
              >
                {loading ? 'Creating...' : 'Create Course'}
              </button>
            </form>
            {error && (
              <p className="text-red-600 text-sm mt-2">{error}</p>
            )}
            {success && (
              <p className="text-green-600 text-sm mt-2">{success}</p>
            )}
          </div>

          {/* Created Courses */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-medium text-gray-900 mb-4">Your Courses</h2>
            {courses.length === 0 ? (
              <p className="text-gray-600">No courses created yet. Create your first course above.</p>
            ) : (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {courses.map((course) => (
                  <div key={course.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex justify-between items-start mb-2">
                      <h3 className="font-medium text-gray-900">{course.name}</h3>
                      <button
                        onClick={() => handleDeleteCourse(course.id)}
                        className="text-red-600 hover:text-red-800 text-sm"
                      >
                        Delete
                      </button>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">Code: <span className="font-mono bg-gray-100 px-2 py-1 rounded">{course.code}</span></p>
                    <p className="text-sm text-gray-600">Students: {course.students.length}</p>
                    <p className="text-sm text-gray-600">Created: {new Date(course.created_at).toLocaleDateString()}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const ModeratorDashboard = () => {
  const { user, logout } = useAuth();
  const [courses, setCourses] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [coursesResponse, statsResponse] = await Promise.all([
        axios.get(`${API}/courses`),
        axios.get(`${API}/admin/stats`)
      ]);
      setCourses(coursesResponse.data);
      setStats(statsResponse.data);
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  };

  const handleDeleteCourse = async (courseId) => {
    if (!window.confirm('Are you sure you want to delete this course? This action cannot be undone.')) {
      return;
    }

    try {
      await axios.delete(`${API}/courses/${courseId}`);
      fetchData(); // Refresh the data
    } catch (error) {
      console.error('Error deleting course:', error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gray-900">Moderator Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Welcome, {user.username}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0 space-y-6">
          {/* System Overview */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-medium text-gray-900 mb-4">System Overview</h2>
            {stats ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <h3 className="text-sm font-medium text-blue-600">Total Users</h3>
                  <p className="text-2xl font-bold text-blue-900">{stats.total_users}</p>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <h3 className="text-sm font-medium text-green-600">Total Courses</h3>
                  <p className="text-2xl font-bold text-green-900">{stats.total_courses || courses.length}</p>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg">
                  <h3 className="text-sm font-medium text-yellow-600">Total Questions</h3>
                  <p className="text-2xl font-bold text-yellow-900">{stats.total_questions}</p>
                </div>
                <div className="bg-purple-50 p-4 rounded-lg">
                  <h3 className="text-sm font-medium text-purple-600">Total Polls</h3>
                  <p className="text-2xl font-bold text-purple-900">{stats.total_polls}</p>
                </div>
              </div>
            ) : (
              <p className="text-gray-600">Loading statistics...</p>
            )}
          </div>

          {/* All Courses */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-medium text-gray-900 mb-4">All Courses</h2>
            {courses.length === 0 ? (
              <p className="text-gray-600">No courses exist yet.</p>
            ) : (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {courses.map((course) => (
                  <div key={course.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex justify-between items-start mb-2">
                      <h3 className="font-medium text-gray-900">{course.name}</h3>
                      <button
                        onClick={() => handleDeleteCourse(course.id)}
                        className="text-red-600 hover:text-red-800 text-sm"
                      >
                        Delete
                      </button>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">Code: <span className="font-mono bg-gray-100 px-2 py-1 rounded">{course.code}</span></p>
                    <p className="text-sm text-gray-600">Professor: {course.professor_name}</p>
                    <p className="text-sm text-gray-600">Students: {course.students.length}</p>
                    <p className="text-sm text-gray-600">Created: {new Date(course.created_at).toLocaleDateString()}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const { user } = useAuth();
  
  // Add null check for user
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  
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
    <ErrorBoundary>
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
    </ErrorBoundary>
  );
}

export default App; 