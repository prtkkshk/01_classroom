import React, { useState, useEffect, createContext, useContext, Component } from 'react';
import { HashRouter as Router, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Backend URL configuration
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'https://zero1-classroom-1.onrender.com';
const cleanBackendUrl = BACKEND_URL.replace(/\/$/, '');
const API = `${cleanBackendUrl}/api`;

// Add axios interceptors for better error handling
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Axios error:', {
      config: error.config,
      response: error.response,
      message: error.message
    });
    
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
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }
    } else {
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
      if (!error.response) {
        return { success: false, error: 'Network error - cannot connect to server. Please check your internet connection.' };
      }
      
      if (error.response?.status === 404) {
        return { success: false, error: 'API endpoint not found. Please check backend URL.' };
      }
      
      if (error.response?.status === 0) {
        return { success: false, error: 'Cannot connect to server. Please check if backend is running.' };
      }
      
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

  const register = async (name, rollNumber, email, password) => {
    try {
      const response = await axios.post(`${API}/register`, { name, roll_number: rollNumber, email, password });
      
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
      if (!error.response) {
        return { success: false, error: 'Network error - cannot connect to server. Please check your internet connection.' };
      }
      
      if (error.response?.status === 404) {
        return { success: false, error: 'API endpoint not found. Please check backend URL.' };
      }
      
      if (error.response?.status === 0) {
        return { success: false, error: 'Cannot connect to server. Please check if backend is running.' };
      }
      
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

// Course Context
const CourseContext = createContext();

const CourseProvider = ({ children }) => {
  const [currentCourse, setCurrentCourse] = useState(() => {
    const saved = localStorage.getItem('currentCourse');
    return saved ? JSON.parse(saved) : null;
  });
  const [courses, setCourses] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(Date.now());

  const fetchCourses = async () => {
    try {
      const response = await axios.get(`${API}/courses`);
      setCourses(response.data);
    } catch (error) {
      console.error('Error fetching courses:', error);
    }
  };

  const createCourse = async (name) => {
    try {
      const response = await axios.post(`${API}/courses`, { name });
      await fetchCourses();
      return { success: true, course: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Failed to create course' };
    }
  };

  const joinCourse = async (code) => {
    try {
      await axios.post(`${API}/courses/join`, { code });
      await fetchCourses();
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Failed to join course' };
    }
  };

  const deleteCourse = async (courseId) => {
    try {
      await axios.delete(`${API}/courses/${courseId}`);
      await fetchCourses();
      if (currentCourse?.id === courseId) {
        setCurrentCourse(null);
        localStorage.removeItem('currentCourse');
      }
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Failed to delete course' };
    }
  };

  // Wrapper function to persist currentCourse state
  const setCurrentCoursePersistent = (course) => {
    setCurrentCourse(course);
    if (course) {
      localStorage.setItem('currentCourse', JSON.stringify(course));
    } else {
      localStorage.removeItem('currentCourse');
    }
  };

  // Real-time update function
  const refreshData = () => {
    setLastUpdate(Date.now());
    fetchCourses();
  };

  // Set up periodic refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      refreshData();
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, []);

  return (
    <CourseContext.Provider value={{
      currentCourse,
      setCurrentCourse: setCurrentCoursePersistent,
      courses,
      fetchCourses,
      createCourse,
      joinCourse,
      deleteCourse,
      loading,
      lastUpdate,
      refreshData
    }}>
      {children}
    </CourseContext.Provider>
  );
};

const useCourse = () => {
  const context = useContext(CourseContext);
  if (!context) {
    throw new Error('useCourse must be used within a CourseProvider');
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
  const location = useLocation();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

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
      // Redirect to the page they were trying to access, or home if none
      const from = location.state?.from?.pathname || '/';
      navigate(from, { replace: true });
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl p-6 sm:p-8 w-full max-w-md mx-4">
        <div className="text-center mb-6 sm:mb-8">
          <div className="flex flex-row items-center justify-center gap-2 sm:gap-3 mb-2">
            <img 
              src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
              alt="Classroom Logo" 
              style={{ width: 48, height: 48 }} 
              className="sm:w-14 sm:h-14"
              onError={(e) => {
                e.target.style.display = 'none';
                console.error('Logo image failed to load');
              }}
            />
            <span className="text-2xl sm:text-3xl font-bold text-gray-900">Classroom</span>
          </div>
          <p className="text-gray-600 text-sm sm:text-base">Sign in to your Classroom account</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 sm:space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Roll Number / User ID</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 sm:px-4 py-2.5 sm:py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors text-base"
              placeholder="Enter your roll number or user ID"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 sm:px-4 py-2.5 sm:py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors text-base"
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
            className="w-full bg-indigo-600 text-white py-2.5 sm:py-3 px-4 rounded-lg font-medium hover:bg-indigo-700 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors disabled:opacity-50 text-base"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-gray-600 text-sm sm:text-base">
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
  const [name, setName] = useState('');
  const [rollNumber, setRollNumber] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!name.trim()) {
      setError('Name is required');
      return;
    }
    
    if (!rollNumber.trim()) {
      setError('Roll number is required');
      return;
    }
    
    if (!email.trim()) {
      setError('Email is required');
      return;
    }
    
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

    const result = await register(name.trim(), rollNumber.trim(), email.trim(), password);
    if (result.success) {
      // Redirect to the page they were trying to access, or home if none
      const from = location.state?.from?.pathname || '/';
      navigate(from, { replace: true });
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl p-6 sm:p-8 w-full max-w-md mx-4">
        <div className="text-center mb-6 sm:mb-8">
          <div className="flex flex-row items-center justify-center gap-2 sm:gap-3 mb-2">
            <img 
              src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
              alt="Classroom Logo" 
              style={{ width: 48, height: 48 }} 
              className="sm:w-14 sm:h-14"
              onError={(e) => {
                e.target.style.display = 'none';
                console.error('Logo image failed to load');
              }}
            />
            <span className="text-2xl sm:text-3xl font-bold text-gray-900">Classroom</span>
          </div>
          <div className="text-gray-500 mb-2 text-sm sm:text-base">Create Account</div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 sm:space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 sm:px-4 py-2.5 sm:py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors text-base"
              placeholder="Enter your name"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Roll Number</label>
            <input
              type="text"
              value={rollNumber}
              onChange={(e) => setRollNumber(e.target.value)}
              className="w-full px-3 sm:px-4 py-2.5 sm:py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors text-base"
              placeholder="Enter your roll number"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 sm:px-4 py-2.5 sm:py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors text-base"
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
              className="w-full px-3 sm:px-4 py-2.5 sm:py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors text-base"
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
            className="w-full bg-indigo-600 text-white py-2.5 sm:py-3 px-4 rounded-lg font-medium hover:bg-indigo-700 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors disabled:opacity-50 text-base"
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-gray-600 text-sm sm:text-base">
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

// Course Selection Component
const CourseSelection = () => {
  const { user, logout } = useAuth();
  const { courses, fetchCourses, createCourse, joinCourse, deleteCourse, setCurrentCourse, lastUpdate } = useCourse();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showJoinForm, setShowJoinForm] = useState(false);
  const [courseName, setCourseName] = useState('');
  const [courseCode, setCourseCode] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchCourses();
  }, []);

  // Real-time updates when lastUpdate changes
  useEffect(() => {
    if (lastUpdate) {
      fetchCourses();
    }
  }, [lastUpdate]);

  const handleCreateCourse = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    const result = await createCourse(courseName);
    if (result.success) {
      setShowCreateForm(false);
      setCourseName('');
      setSuccess(`Course created successfully! Course code: ${result.course.code}`);
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleJoinCourse = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    const result = await joinCourse(courseCode.toUpperCase());
    if (result.success) {
      setShowJoinForm(false);
      setCourseCode('');
      setSuccess('Successfully joined the course!');
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  const handleDeleteCourse = async (courseId) => {
    if (window.confirm('Are you sure you want to delete this course?')) {
      const result = await deleteCourse(courseId);
      if (result.success) {
        setSuccess('Course deleted successfully!');
      } else {
        setError(result.error);
      }
    }
  };

  const handleEnterCourse = (course) => {
    setCurrentCourse(course);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center py-3 sm:py-4 gap-2 sm:gap-3">
            <div className="flex items-center justify-between sm:justify-start w-full sm:w-auto">
              <div className="flex items-center min-w-0 flex-1 sm:flex-none">
                <img 
                  src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
                  alt="Classroom Logo" 
                  style={{ width: 28, height: 28, marginRight: 6 }} 
                  className="sm:w-9 sm:h-9 sm:mr-2"
                  onError={(e) => {
                    e.target.style.display = 'none';
                  }}
                />
                <h1 className="text-lg sm:text-2xl font-bold text-gray-900 truncate">Classroom</h1>
                <span className={`ml-2 sm:ml-3 px-2 py-1 rounded-full text-xs font-medium flex-shrink-0 ${
                  user.role === 'student' ? 'bg-blue-100 text-blue-800' :
                  user.role === 'professor' ? 'bg-purple-100 text-purple-800' :
                  'bg-red-100 text-red-800'
                }`}>
                  {user.role}
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between sm:justify-end gap-2 sm:gap-3 w-full sm:w-auto">
              <span className="text-xs sm:text-base text-gray-700 truncate">
                Hello, {user.role === 'professor' ? `Prof. ${user.name}` : user.role === 'student' ? `${user.name} (${user.roll_number})` : user.username}!
              </span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg hover:bg-red-700 transition-colors text-xs sm:text-sm flex-shrink-0"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-8">
        <div className="mb-6 sm:mb-8 flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
          <h2 className="text-2xl sm:text-3xl font-bold text-gray-900">My Courses</h2>
          
          <div>
            {user.role === 'professor' && (
              <button
                onClick={() => setShowCreateForm(true)}
                className="w-full sm:w-auto bg-indigo-600 text-white px-6 py-3 rounded-lg hover:bg-indigo-700 transition-colors"
              >
                Create New Course
              </button>
            )}
            
            {user.role === 'student' && (
              <button
                onClick={() => setShowJoinForm(true)}
                className="w-full sm:w-auto bg-green-600 text-white px-6 py-3 rounded-lg hover:bg-green-700 transition-colors"
              >
                Join Course
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700 mb-6">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-green-700 mb-6">
            {success}
          </div>
        )}

        {/* Create Course Modal */}
        {showCreateForm && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-lg p-4 sm:p-6 w-full max-w-md mx-4">
              <h3 className="text-lg font-semibold mb-4">Create New Course</h3>
              <form onSubmit={handleCreateCourse} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Course Name</label>
                  <input
                    type="text"
                    value={courseName}
                    onChange={(e) => setCourseName(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    placeholder="Enter course name"
                    required
                  />
                </div>
                <div className="flex space-x-3">
                  <button
                    type="submit"
                    disabled={loading}
                    className="flex-1 bg-indigo-600 text-white py-2 px-4 rounded-lg hover:bg-indigo-700 disabled:opacity-50"
                  >
                    {loading ? 'Creating...' : 'Create Course'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowCreateForm(false)}
                    className="flex-1 bg-gray-600 text-white py-2 px-4 rounded-lg hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Join Course Modal */}
        {showJoinForm && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-lg p-4 sm:p-6 w-full max-w-md mx-4">
              <h3 className="text-lg font-semibold mb-4">Join Course</h3>
              <form onSubmit={handleJoinCourse} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Course Code</label>
                  <input
                    type="text"
                    value={courseCode}
                    onChange={(e) => setCourseCode(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    placeholder="Enter 8-letter course code"
                    maxLength="8"
                    required
                  />
                </div>
                <div className="flex space-x-3">
                  <button
                    type="submit"
                    disabled={loading}
                    className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 disabled:opacity-50"
                  >
                    {loading ? 'Joining...' : 'Join Course'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowJoinForm(false)}
                    className="flex-1 bg-gray-600 text-white py-2 px-4 rounded-lg hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Courses Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
          {courses.map((course) => (
            <div key={course.id} className="bg-white rounded-lg shadow-sm border p-4 sm:p-6">
              <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-3 mb-4">
                <div className="flex-1">
                  <h3 className="text-lg sm:text-xl font-semibold text-gray-900 mb-2">{course.name}</h3>
                  <div className="space-y-1">
                    <p className="text-sm text-gray-600">Code: <span className="font-mono bg-gray-100 px-2 py-1 rounded text-xs">{course.code}</span></p>
                    <p className="text-sm text-gray-600">Professor: {course.professor_name}</p>
                    <p className="text-sm text-gray-600">Students: {course.students?.length || 0}</p>
                  </div>
                </div>
                {user.role === 'professor' && course.professor_id === user.id && (
                  <button
                    onClick={() => handleDeleteCourse(course.id)}
                    className="text-red-600 hover:text-red-800 text-sm self-start"
                  >
                    Delete
                  </button>
                )}
              </div>
              <button
                onClick={() => handleEnterCourse(course)}
                className="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 transition-colors text-sm sm:text-base"
              >
                Enter Course
              </button>
            </div>
          ))}
        </div>

        {courses.length === 0 && (
          <div className="text-center py-8 sm:py-12">
            <p className="text-gray-500 text-base sm:text-lg px-4">
              {user.role === 'professor' 
                ? 'You haven\'t created any courses yet. Create your first course to get started!'
                : 'You haven\'t joined any courses yet. Join a course using a course code!'
              }
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

// Poll Card Component
const PollCard = ({ poll, onVote, showResults = false }) => {
  const [userVote, setUserVote] = useState(null);
  const [hasVoted, setHasVoted] = useState(false);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!showResults) {
      checkUserVote();
    } else {
      fetchResults();
    }
  }, [poll.id, showResults]);

  const checkUserVote = async () => {
    try {
      const response = await axios.get(`${API}/polls/${poll.id}/user-vote`);
      setHasVoted(response.data.voted);
      setUserVote(response.data.option);
    } catch (error) {
      console.error('Error checking user vote:', error);
    }
  };

  const fetchResults = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API}/polls/${poll.id}/results`);
      setResults(response.data);
    } catch (error) {
      console.error('Error fetching poll results:', error);
    }
    setLoading(false);
  };

  const handleVote = async (option) => {
    await onVote(poll.id, option);
    setHasVoted(true);
    setUserVote(option);
  };

  if (showResults && loading) {
    return (
      <div className="bg-white border rounded-lg p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
          <div className="space-y-2">
            <div className="h-3 bg-gray-200 rounded"></div>
            <div className="h-3 bg-gray-200 rounded w-5/6"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white border rounded-lg p-6">
      <h3 className="text-lg font-semibold mb-4">{poll.question}</h3>
      <div className="space-y-3">
        {poll.options.map((option, index) => {
          if (showResults && results) {
            const voteCount = results.votes[option] || 0;
            const percentage = results.total_votes > 0 ? (voteCount / results.total_votes) * 100 : 0;
            
            return (
              <div key={index} className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>{option}</span>
                  <span>{voteCount} votes ({percentage.toFixed(1)}%)</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-indigo-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${percentage}%` }}
                  ></div>
                </div>
              </div>
            );
          }

          return (
            <div key={index} className="flex items-center space-x-3">
              <button
                onClick={() => handleVote(option)}
                disabled={hasVoted}
                className={`flex-1 p-3 text-left rounded-lg border transition-colors ${
                  hasVoted
                    ? userVote === option
                      ? 'bg-indigo-50 border-indigo-200 text-indigo-800'
                      : 'bg-gray-50 border-gray-200 text-gray-600 cursor-not-allowed'
                    : 'border-gray-300 hover:bg-gray-50'
                }`}
              >
                {option}
                {hasVoted && userVote === option && (
                  <span className="ml-2 text-indigo-600">✓</span>
                )}
              </button>
            </div>
          );
        })}
      </div>
      <div className="mt-4 text-sm text-gray-500">
        {showResults && results && (
          <span>Total votes: {results.total_votes || 0} | </span>
        )}
        <span>Created: {new Date(poll.created_at).toLocaleDateString()}</span>
      </div>
    </div>
  );
};

// Student Dashboard Component
const StudentDashboard = () => {
  const { user, logout } = useAuth();
  const { currentCourse, setCurrentCourse, lastUpdate } = useCourse();
  const [activeTab, setActiveTab] = useState('questions');
  const [questions, setQuestions] = useState([]);
  const [myQuestions, setMyQuestions] = useState([]);
  const [polls, setPolls] = useState([]);
  const [loading, setLoading] = useState(false);

  // Question form state
  const [questionText, setQuestionText] = useState('');
  const [isAnonymous, setIsAnonymous] = useState(false);
  const [editingQuestion, setEditingQuestion] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (currentCourse) {
      fetchQuestions();
      fetchMyQuestions();
      fetchPolls();
    }
  }, [currentCourse]);

  // Real-time updates when lastUpdate changes
  useEffect(() => {
    if (currentCourse && lastUpdate) {
      fetchQuestions();
      fetchMyQuestions();
      fetchPolls();
    }
  }, [lastUpdate]);

  const fetchQuestions = async () => {
    try {
      const response = await axios.get(`${API}/questions?course_id=${currentCourse.id}`);
      setQuestions(response.data);
    } catch (error) {
      console.error('Error fetching questions:', error);
    }
  };

  const fetchMyQuestions = async () => {
    try {
      const response = await axios.get(`${API}/questions/my?course_id=${currentCourse.id}`);
      setMyQuestions(response.data);
    } catch (error) {
      console.error('Error fetching my questions:', error);
    }
  };

  const fetchPolls = async () => {
    try {
      const response = await axios.get(`${API}/polls?course_id=${currentCourse.id}`);
      setPolls(response.data);
    } catch (error) {
      console.error('Error fetching polls:', error);
    }
  };

  const handleSubmitQuestion = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      if (editingQuestion) {
        await axios.put(`${API}/questions/${editingQuestion.id}`, {
          question_text: questionText
        });
        setEditingQuestion(null);
        setSuccess('Question updated successfully!');
      } else {
        await axios.post(`${API}/questions`, {
          question_text: questionText,
          course_id: currentCourse.id,
          is_anonymous: isAnonymous
        });
        setSuccess('Question submitted successfully!');
      }
      
      setQuestionText('');
      setIsAnonymous(false);
      fetchQuestions();
      fetchMyQuestions();
    } catch (error) {
      setError(error.response?.data?.detail || 'Error submitting question');
    }
    setLoading(false);
  };

  const handleEditQuestion = (question) => {
    setEditingQuestion(question);
    setQuestionText(question.question_text);
    setIsAnonymous(question.is_anonymous);
  };

  const handleDeleteQuestion = async (questionId) => {
    if (window.confirm('Are you sure you want to delete this question?')) {
      try {
        await axios.delete(`${API}/questions/${questionId}`);
        setSuccess('Question deleted successfully!');
        fetchQuestions();
        fetchMyQuestions();
      } catch (error) {
        setError('Error deleting question');
      }
    }
  };

  const handleMarkAsAnswered = async (questionId) => {
    try {
      await axios.put(`${API}/questions/${questionId}`, {
        is_answered: true
      });
      setSuccess('Question marked as answered!');
      fetchQuestions();
      fetchMyQuestions();
    } catch (error) {
      setError('Error marking question as answered');
    }
  };

  const handleVote = async (pollId, option) => {
    try {
      await axios.post(`${API}/polls/${pollId}/vote`, {
        poll_id: pollId,
        option_selected: option
      });
      setSuccess('Vote submitted successfully!');
      fetchPolls();
    } catch (error) {
      setError('Error submitting vote');
    }
  };

  const cancelEdit = () => {
    setEditingQuestion(null);
    setQuestionText('');
    setIsAnonymous(false);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center py-3 sm:py-4 gap-2 sm:gap-3">
            <div className="flex items-center justify-between sm:justify-start w-full sm:w-auto">
              <div className="flex items-center min-w-0 flex-1 sm:flex-none">
                <button
                  onClick={() => setCurrentCourse(null)}
                  className="mr-2 sm:mr-4 text-gray-600 hover:text-gray-800 text-xs sm:text-sm flex-shrink-0"
                >
                  ← Back
                </button>
                <img 
                  src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
                  alt="Classroom Logo" 
                  style={{ width: 28, height: 28, marginRight: 6 }}
                  className="sm:w-9 sm:h-9 sm:mr-2"
                  onError={(e) => { e.target.style.display = 'none'; }}
                />
                <h1 className="text-lg sm:text-2xl font-bold text-gray-900 truncate">{currentCourse?.name}</h1>
                <span className="ml-2 sm:ml-3 px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs font-medium flex-shrink-0">
                  Student
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between sm:justify-end gap-2 sm:gap-3 w-full sm:w-auto">
              <span className="text-xs sm:text-base text-gray-700 truncate">Hello, {user.name} ({user.roll_number})!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg hover:bg-red-700 transition-colors text-xs sm:text-sm flex-shrink-0"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700 mb-6">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-green-700 mb-6">
            {success}
          </div>
        )}

        <div className="bg-white rounded-lg shadow-sm mb-8">
          <div className="border-b">
            <nav className="flex flex-wrap space-x-4 sm:space-x-8 px-4 sm:px-6">
              <button
                onClick={() => setActiveTab('questions')}
                className={`py-3 sm:py-4 px-1 border-b-2 font-medium text-xs sm:text-sm ${
                  activeTab === 'questions'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Ask Questions
              </button>
              <button
                onClick={() => setActiveTab('forum')}
                className={`py-3 sm:py-4 px-1 border-b-2 font-medium text-xs sm:text-sm ${
                  activeTab === 'forum'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Questions Forum
              </button>
              <button
                onClick={() => setActiveTab('polls')}
                className={`py-3 sm:py-4 px-1 border-b-2 font-medium text-xs sm:text-sm ${
                  activeTab === 'polls'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Polls
              </button>
            </nav>
          </div>

          <div className="p-4 sm:p-6">
            {activeTab === 'questions' && (
              <div className="space-y-6 sm:space-y-8">
                <div className="bg-gray-50 rounded-lg p-4 sm:p-6">
                  <h2 className="text-xl font-semibold mb-4">
                    {editingQuestion ? 'Edit Question' : 'Ask a Question'}
                  </h2>
                  <form onSubmit={handleSubmitQuestion} className="space-y-4">
                    <div>
                      <textarea
                        value={questionText}
                        onChange={(e) => setQuestionText(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
                        placeholder="What's your question?"
                        rows="4"
                        required
                      />
                    </div>
                    <div className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        id="anonymous"
                        checked={isAnonymous}
                        onChange={(e) => setIsAnonymous(e.target.checked)}
                        className="w-4 h-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500"
                      />
                      <label htmlFor="anonymous" className="text-sm text-gray-700">
                        Ask anonymously
                      </label>
                    </div>
                    <div className="flex space-x-3">
                      <button
                        type="submit"
                        disabled={loading}
                        className="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
                      >
                        {loading ? 'Submitting...' : editingQuestion ? 'Update Question' : 'Ask Question'}
                      </button>
                      {editingQuestion && (
                        <button
                          type="button"
                          onClick={cancelEdit}
                          className="bg-gray-600 text-white px-6 py-2 rounded-lg hover:bg-gray-700 transition-colors"
                        >
                          Cancel
                        </button>
                      )}
                    </div>
                  </form>
                </div>

                <div>
                  <h3 className="text-lg font-semibold mb-4">My Questions</h3>
                  <div className="space-y-4">
                    {myQuestions.map((question) => (
                      <div key={question.id} className="bg-white border rounded-lg p-4">
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="font-medium text-gray-900">{question.question_text}</h4>
                          <div className="flex space-x-2">
                            {!question.is_answered && (
                              <>
                                <button
                                  onClick={() => handleEditQuestion(question)}
                                  className="text-blue-600 hover:text-blue-800 text-sm"
                                >
                                  Edit
                                </button>
                                <button
                                  onClick={() => handleMarkAsAnswered(question.id)}
                                  className="text-green-600 hover:text-green-800 text-sm"
                                >
                                  Mark Answered
                                </button>
                              </>
                            )}
                            <button
                              onClick={() => handleDeleteQuestion(question.id)}
                              className="text-red-600 hover:text-red-800 text-sm"
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                        <div className="flex items-center space-x-4 text-sm text-gray-500">
                          <span>By: {question.username}</span>
                          <span>{new Date(question.created_at).toLocaleDateString()}</span>
                          {question.is_answered && (
                            <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full">
                              Answered
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                    {myQuestions.length === 0 && (
                      <p className="text-gray-600">You haven't asked any questions yet.</p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'forum' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Questions Forum</h2>
                <div className="space-y-4">
                  {questions.map((question) => (
                    <div key={question.id} className="bg-white border rounded-lg p-4">
                      <h4 className="font-medium text-gray-900 mb-2">{question.question_text}</h4>
                      <div className="flex items-center space-x-4 text-sm text-gray-500">
                        <span>By: {question.username}</span>
                        <span>{new Date(question.created_at).toLocaleDateString()}</span>
                        {question.is_answered && (
                          <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full">
                            Answered
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                  {questions.length === 0 && (
                    <p className="text-gray-600">No questions posted yet.</p>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'polls' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Polls</h2>
                <div className="space-y-6">
                  {polls.map((poll) => (
                    <PollCard key={poll.id} poll={poll} onVote={handleVote} />
                  ))}
                  {polls.length === 0 && (
                    <p className="text-gray-600">No polls available yet.</p>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Professor Dashboard Component
const ProfessorDashboard = () => {
  const { user, logout } = useAuth();
  const { currentCourse, setCurrentCourse, lastUpdate } = useCourse();
  const [activeTab, setActiveTab] = useState('questions');
  const [questions, setQuestions] = useState([]);
  const [polls, setPolls] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Poll form state
  const [pollQuestion, setPollQuestion] = useState('');
  const [pollOptions, setPollOptions] = useState(['', '']);

  useEffect(() => {
    if (currentCourse) {
      fetchQuestions();
      fetchPolls();
    }
  }, [currentCourse]);

  // Real-time updates when lastUpdate changes
  useEffect(() => {
    if (currentCourse && lastUpdate) {
      fetchQuestions();
      fetchPolls();
    }
  }, [lastUpdate]);

  const fetchQuestions = async () => {
    try {
      const response = await axios.get(`${API}/questions?course_id=${currentCourse.id}`);
      setQuestions(response.data);
    } catch (error) {
      console.error('Error fetching questions:', error);
    }
  };

  const fetchPolls = async () => {
    try {
      const response = await axios.get(`${API}/polls?course_id=${currentCourse.id}`);
      setPolls(response.data);
    } catch (error) {
      console.error('Error fetching polls:', error);
    }
  };

  const handleMarkAsAnswered = async (questionId) => {
    try {
      await axios.put(`${API}/questions/${questionId}`, {
        is_answered: true
      });
      setSuccess('Question marked as answered!');
      fetchQuestions();
    } catch (error) {
      setError('Error marking question as answered');
    }
  };

  const handleCreatePoll = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.post(`${API}/polls`, {
        question: pollQuestion,
        course_id: currentCourse.id,
        options: pollOptions.filter(option => option.trim() !== '')
      });
      
      setPollQuestion('');
      setPollOptions(['', '']);
      setSuccess('Poll created successfully!');
      fetchPolls();
    } catch (error) {
      setError('Error creating poll');
    }
    setLoading(false);
  };

  const addPollOption = () => {
    setPollOptions([...pollOptions, '']);
  };

  const removePollOption = (index) => {
    setPollOptions(pollOptions.filter((_, i) => i !== index));
  };

  const updatePollOption = (index, value) => {
    const newOptions = [...pollOptions];
    newOptions[index] = value;
    setPollOptions(newOptions);
  };

  const handleDeletePoll = async (pollId) => {
    if (window.confirm('Are you sure you want to delete this poll and all its votes?')) {
      try {
        await axios.delete(`${API}/polls/${pollId}`);
        setSuccess('Poll deleted successfully!');
        fetchPolls();
      } catch (error) {
        setError('Error deleting poll');
      }
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center py-3 sm:py-4 gap-2 sm:gap-3">
            <div className="flex items-center justify-between sm:justify-start w-full sm:w-auto">
              <div className="flex items-center min-w-0 flex-1 sm:flex-none">
                <button
                  onClick={() => setCurrentCourse(null)}
                  className="mr-2 sm:mr-4 text-gray-600 hover:text-gray-800 text-xs sm:text-sm flex-shrink-0"
                >
                  ← Back
                </button>
                <img 
                  src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
                  alt="Classroom Logo" 
                  style={{ width: 28, height: 28, marginRight: 6 }}
                  className="sm:w-9 sm:h-9 sm:mr-2"
                  onError={(e) => { e.target.style.display = 'none'; }}
                />
                <h1 className="text-lg sm:text-2xl font-bold text-gray-900 truncate">{currentCourse?.name}</h1>
                <span className="ml-2 sm:ml-3 px-2 py-1 bg-purple-100 text-purple-800 rounded-full text-xs font-medium flex-shrink-0">
                  Professor
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between sm:justify-end gap-2 sm:gap-3 w-full sm:w-auto">
              <span className="text-xs sm:text-base text-gray-700 truncate">Hello, Prof. {user.name}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg hover:bg-red-700 transition-colors text-xs sm:text-sm flex-shrink-0"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700 mb-6">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-green-700 mb-6">
            {success}
          </div>
        )}

        <div className="bg-white rounded-lg shadow-sm mb-8">
          <div className="border-b">
            <nav className="flex flex-wrap space-x-4 sm:space-x-8 px-4 sm:px-6">
              <button
                onClick={() => setActiveTab('questions')}
                className={`py-3 sm:py-4 px-1 border-b-2 font-medium text-xs sm:text-sm ${
                  activeTab === 'questions'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Questions Forum
              </button>
              <button
                onClick={() => setActiveTab('polls')}
                className={`py-3 sm:py-4 px-1 border-b-2 font-medium text-xs sm:text-sm ${
                  activeTab === 'polls'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Polls
              </button>
            </nav>
          </div>

          <div className="p-4 sm:p-6">
            {activeTab === 'questions' && (
              <div>
                <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6">Questions Forum</h2>
                <div className="space-y-4">
                  {questions.map((question) => (
                    <div key={question.id} className="bg-white border rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <h4 className="font-medium text-gray-900">{question.question_text}</h4>
                        {!question.is_answered && (
                          <button
                            onClick={() => handleMarkAsAnswered(question.id)}
                            className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700 transition-colors"
                          >
                            Mark as Answered
                          </button>
                        )}
                      </div>
                      <div className="flex items-center space-x-4 text-sm text-gray-500">
                        <span>By: {question.username}</span>
                        <span>{new Date(question.created_at).toLocaleDateString()}</span>
                        {question.is_answered && (
                          <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full">
                            Answered
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                  {questions.length === 0 && (
                    <p className="text-gray-600">No questions posted yet.</p>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'polls' && (
              <div className="space-y-8">
                <div className="bg-gray-50 rounded-lg p-6">
                  <h2 className="text-xl font-semibold mb-4">Create New Poll</h2>
                  <form onSubmit={handleCreatePoll} className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Poll Question
                      </label>
                      <input
                        type="text"
                        value={pollQuestion}
                        onChange={(e) => setPollQuestion(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
                        placeholder="Enter your poll question"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Options
                      </label>
                      {pollOptions.map((option, index) => (
                        <div key={index} className="flex items-center space-x-2 mb-2">
                          <input
                            type="text"
                            value={option}
                            onChange={(e) => updatePollOption(index, e.target.value)}
                            className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
                            placeholder={`Option ${index + 1}`}
                            required
                          />
                          {pollOptions.length > 2 && (
                            <button
                              type="button"
                              onClick={() => removePollOption(index)}
                              className="text-red-600 hover:text-red-800"
                            >
                              Remove
                            </button>
                          )}
                        </div>
                      ))}
                      <button
                        type="button"
                        onClick={addPollOption}
                        className="text-indigo-600 hover:text-indigo-800 text-sm"
                      >
                        + Add Option
                      </button>
                    </div>
                    <button
                      type="submit"
                      disabled={loading}
                      className="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
                    >
                      {loading ? 'Creating Poll...' : 'Create Poll'}
                    </button>
                  </form>
                </div>

                <div>
                  <h3 className="text-lg font-semibold mb-4">My Polls</h3>
                  <div className="space-y-6">
                    {polls.map((poll) => (
                      <div key={poll.id} className="relative">
                        <div className="absolute top-4 right-4 z-10">
                          <button
                            onClick={() => handleDeletePoll(poll.id)}
                            className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                        <PollCard poll={poll} showResults={true} />
                      </div>
                    ))}
                    {polls.length === 0 && (
                      <p className="text-gray-600">You haven't created any polls yet.</p>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Moderator Dashboard Component
const ModeratorDashboard = () => {
  const { user, logout } = useAuth();
  const { courses, fetchCourses, deleteCourse, lastUpdate } = useCourse();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({});
  const [users, setUsers] = useState([]);
  const [questions, setQuestions] = useState([]);
  const [polls, setPolls] = useState([]);
  const [votes, setVotes] = useState([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Professor creation state
  const [professorName, setProfessorName] = useState('');
  const [professorUserid, setProfessorUserid] = useState('');
  const [professorEmail, setProfessorEmail] = useState('');
  const [professorPassword, setProfessorPassword] = useState('');
  const [creatingProfessor, setCreatingProfessor] = useState(false);

  useEffect(() => {
    fetchCourses();
    fetchStats();
    fetchUsers();
    fetchQuestions();
    fetchPolls();
    fetchVotes();
  }, []);

  // Real-time updates when lastUpdate changes
  useEffect(() => {
    if (lastUpdate) {
      fetchCourses();
      fetchStats();
      fetchUsers();
      fetchQuestions();
      fetchPolls();
      fetchVotes();
    }
  }, [lastUpdate]);

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/admin/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await axios.get(`${API}/admin/users`);
      setUsers(response.data);
    } catch (error) {
      console.error('Error fetching users:', error);
    }
  };

  const fetchQuestions = async () => {
    try {
      const response = await axios.get(`${API}/questions`);
      setQuestions(response.data);
    } catch (error) {
      console.error('Error fetching questions:', error);
    }
  };

  const fetchPolls = async () => {
    try {
      const response = await axios.get(`${API}/polls`);
      setPolls(response.data);
    } catch (error) {
      console.error('Error fetching polls:', error);
    }
  };

  const fetchVotes = async () => {
    try {
      const response = await axios.get(`${API}/admin/votes`);
      setVotes(response.data);
    } catch (error) {
      console.error('Error fetching votes:', error);
    }
  };

  const handleDeleteUser = async (userId) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      try {
        await axios.delete(`${API}/admin/users/${userId}`);
        setSuccess('User deleted successfully!');
        fetchUsers();
        fetchStats();
      } catch (error) {
        setError('Error deleting user');
      }
    }
  };

  const handleDeleteQuestion = async (questionId) => {
    if (window.confirm('Are you sure you want to delete this question?')) {
      try {
        await axios.delete(`${API}/admin/questions/${questionId}`);
        setSuccess('Question deleted successfully!');
        fetchQuestions();
        fetchStats();
      } catch (error) {
        setError('Error deleting question');
      }
    }
  };

  const handleDeletePoll = async (pollId) => {
    if (window.confirm('Are you sure you want to delete this poll and all its votes?')) {
      try {
        await axios.delete(`${API}/admin/polls/${pollId}`);
        setSuccess('Poll deleted successfully!');
        fetchPolls();
        fetchVotes();
        fetchStats();
      } catch (error) {
        setError('Error deleting poll');
      }
    }
  };

  const handleDeleteVote = async (voteId) => {
    if (window.confirm('Are you sure you want to delete this vote?')) {
      try {
        await axios.delete(`${API}/admin/votes/${voteId}`);
        setSuccess('Vote deleted successfully!');
        fetchVotes();
        fetchStats();
      } catch (error) {
        setError('Error deleting vote');
      }
    }
  };

  const handleToggleQuestionStatus = async (questionId, currentStatus) => {
    try {
      await axios.put(`${API}/admin/questions/${questionId}`, {
        is_answered: !currentStatus
      });
      setSuccess('Question status updated!');
      fetchQuestions();
      fetchStats();
    } catch (error) {
      setError('Error updating question status');
    }
  };

  const handleDeleteCourse = async (courseId) => {
    if (window.confirm('Are you sure you want to delete this course? This action cannot be undone.')) {
      const result = await deleteCourse(courseId);
      if (result.success) {
        setSuccess('Course deleted successfully!');
        fetchStats();
      } else {
        setError(result.error);
      }
    }
  };

  const handleCreateProfessor = async (e) => {
    e.preventDefault();
    setCreatingProfessor(true);
    setError('');
    setSuccess('');

    try {
      await axios.post(`${API}/admin/create-professor`, {
        name: professorName.trim(),
        userid: professorUserid.trim(),
        email: professorEmail.trim(),
        password: professorPassword
      });
      
      setSuccess('Professor account created successfully!');
      setProfessorName('');
      setProfessorUserid('');
      setProfessorEmail('');
      setProfessorPassword('');
      fetchUsers();
      fetchStats();
    } catch (error) {
      setError(error.response?.data?.detail || 'Error creating professor account');
    }
    setCreatingProfessor(false);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center py-3 sm:py-4 gap-2 sm:gap-3">
            <div className="flex items-center justify-between sm:justify-start w-full sm:w-auto">
              <div className="flex items-center min-w-0 flex-1 sm:flex-none">
                <img 
                  src={`${process.env.PUBLIC_URL}/Untitled_design__2_-removebg-preview.png`} 
                  alt="Classroom Logo" 
                  style={{ width: 28, height: 28, marginRight: 6 }}
                  className="sm:w-9 sm:h-9 sm:mr-2"
                  onError={(e) => { e.target.style.display = 'none'; }}
                />
                <h1 className="text-lg sm:text-2xl font-bold text-gray-900 truncate">Classroom</h1>
                <span className="ml-2 sm:ml-3 px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs font-medium flex-shrink-0">
                  Moderator
                </span>
              </div>
            </div>
            <div className="flex items-center justify-between sm:justify-end gap-2 sm:gap-3 w-full sm:w-auto">
              <span className="text-xs sm:text-base text-gray-700 truncate">Hello, {user.name || user.username}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-2 sm:px-4 py-1.5 sm:py-2 rounded-lg hover:bg-red-700 transition-colors text-xs sm:text-sm flex-shrink-0"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700 mb-6">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-green-700 mb-6">
            {success}
          </div>
        )}

        <div className="bg-white rounded-lg shadow-sm mb-8">
          <div className="border-b">
            <nav className="flex flex-wrap space-x-4 sm:space-x-8 px-4 sm:px-6">
              {['overview', 'courses', 'users', 'create-professor', 'questions', 'polls', 'votes'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`py-3 sm:py-4 px-1 border-b-2 font-medium text-xs sm:text-sm capitalize ${
                    activeTab === tab
                      ? 'border-red-500 text-red-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  {tab === 'create-professor' ? 'Create Professor' : tab}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-4 sm:p-6">
            {activeTab === 'overview' && (
              <div>
                <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6">System Overview</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="bg-blue-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-blue-900">Total Users</h3>
                    <p className="text-3xl font-bold text-blue-600">{stats.total_users || 0}</p>
                    <p className="text-sm text-blue-700">
                      Students: {stats.students || 0} | Professors: {stats.professors || 0} | Moderators: {stats.moderators || 0}
                    </p>
                  </div>
                  <div className="bg-green-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-green-900">Total Courses</h3>
                    <p className="text-3xl font-bold text-green-600">{stats.total_courses || courses.length}</p>
                  </div>
                  <div className="bg-purple-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-purple-900">Questions</h3>
                    <p className="text-3xl font-bold text-purple-600">{stats.total_questions || 0}</p>
                    <p className="text-sm text-purple-700">
                      Answered: {stats.answered_questions || 0} | Unanswered: {stats.unanswered_questions || 0}
                    </p>
                  </div>
                  <div className="bg-orange-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-orange-900">Polls & Votes</h3>
                    <p className="text-3xl font-bold text-orange-600">{stats.total_polls || 0}</p>
                    <p className="text-sm text-orange-700">
                      Total Votes: {stats.total_votes || 0}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'courses' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Course Management</h2>
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
                      <p className="text-sm text-gray-600">Students: {course.students?.length || 0}</p>
                      <p className="text-sm text-gray-600">Created: {new Date(course.created_at).toLocaleDateString()}</p>
                    </div>
                  ))}
                </div>
                {courses.length === 0 && (
                  <p className="text-gray-600">No courses exist yet.</p>
                )}
              </div>
            )}

            {activeTab === 'users' && (
              <div>
                <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6">User Management</h2>
                <div className="space-y-4">
                  {users.map((user) => (
                    <div key={user.id} className="bg-white border rounded-lg p-4">
                      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium text-gray-900 text-sm sm:text-base">{user.username}</h4>
                          <p className="text-xs sm:text-sm text-gray-600">{user.email}</p>
                          {user.name && (
                            <p className="text-xs sm:text-sm text-gray-600">
                              Name: {user.name}
                              {user.roll_number && ` (Roll: ${user.roll_number})`}
                              {user.userid && ` (ID: ${user.userid})`}
                            </p>
                          )}
                          <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium mt-2 ${
                            user.role === 'student' ? 'bg-blue-100 text-blue-800' :
                            user.role === 'professor' ? 'bg-purple-100 text-purple-800' :
                            'bg-red-100 text-red-800'
                          }`}>
                            {user.role}
                          </span>
                        </div>
                        <div className="flex flex-col sm:flex-row gap-2 sm:space-x-2">
                          <button
                            onClick={() => handleDeleteUser(user.id)}
                            disabled={user.role === 'moderator'}
                            className={`px-3 py-2 text-xs sm:text-sm rounded ${
                              user.role === 'moderator'
                                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                                : 'bg-red-600 text-white hover:bg-red-700'
                            }`}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {users.length === 0 && (
                  <p className="text-gray-600">No users found.</p>
                )}
              </div>
            )}

            {activeTab === 'create-professor' && (
              <div>
                <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6">Create Professor Account</h2>
                <div className="bg-gray-50 rounded-lg p-6">
                  <form onSubmit={handleCreateProfessor} className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
                      <input
                        type="text"
                        value={professorName}
                        onChange={(e) => setProfessorName(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                        placeholder="Enter professor's full name"
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">User ID</label>
                      <input
                        type="text"
                        value={professorUserid}
                        onChange={(e) => setProfessorUserid(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                        placeholder="Enter unique user ID"
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
                      <input
                        type="email"
                        value={professorEmail}
                        onChange={(e) => setProfessorEmail(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                        placeholder="Enter professor's email"
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
                      <input
                        type="password"
                        value={professorPassword}
                        onChange={(e) => setProfessorPassword(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                        placeholder="Enter password"
                        required
                      />
                    </div>

                    <div className="sm:col-span-2 mt-2">
                      <button
                        type="submit"
                        disabled={creatingProfessor}
                        className="w-full bg-red-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-red-700 focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition-colors disabled:opacity-50"
                      >
                        {creatingProfessor ? 'Creating Professor...' : 'Create Professor Account'}
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}

            {activeTab === 'questions' && (
              <div>
                <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6">Question Management</h2>
                <div className="space-y-4">
                  {questions.map((question) => (
                    <div key={question.id} className="bg-white border rounded-lg p-4">
                      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium text-gray-900 text-sm sm:text-base break-words">{question.question_text}</h4>
                          <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 text-xs sm:text-sm text-gray-500 mt-2">
                            <span>By: {question.username}</span>
                            <span>{new Date(question.created_at).toLocaleDateString()}</span>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium self-start ${
                              question.is_answered ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                            }`}>
                              {question.is_answered ? 'Answered' : 'Unanswered'}
                            </span>
                          </div>
                        </div>
                        <div className="flex flex-col sm:flex-row gap-2 sm:space-x-2">
                          <button
                            onClick={() => handleToggleQuestionStatus(question.id, question.is_answered)}
                            className={`px-3 py-2 text-xs sm:text-sm rounded ${
                              question.is_answered
                                ? 'bg-yellow-600 text-white hover:bg-yellow-700'
                                : 'bg-green-600 text-white hover:bg-green-700'
                            }`}
                          >
                            {question.is_answered ? 'Mark Unanswered' : 'Mark Answered'}
                          </button>
                          <button
                            onClick={() => handleDeleteQuestion(question.id)}
                            className="bg-red-600 text-white px-3 py-2 rounded text-xs sm:text-sm hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {questions.length === 0 && (
                  <p className="text-gray-600">No questions found.</p>
                )}
              </div>
            )}

            {activeTab === 'polls' && (
              <div>
                <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6">Poll Management</h2>
                <div className="space-y-4">
                  {polls.map((poll) => (
                    <div key={poll.id} className="bg-white border rounded-lg p-4">
                      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium text-gray-900 text-sm sm:text-base break-words">{poll.question}</h4>
                          <div className="mt-2">
                            <p className="text-xs sm:text-sm text-gray-600">Options:</p>
                            <ul className="list-disc list-inside text-xs sm:text-sm text-gray-700 mt-1">
                              {poll.options.map((option, index) => (
                                <li key={index} className="break-words">{option}</li>
                              ))}
                            </ul>
                          </div>
                          <p className="text-xs sm:text-sm text-gray-500 mt-2">
                            Created: {new Date(poll.created_at).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="flex flex-col sm:flex-row gap-2 sm:space-x-2">
                          <button
                            onClick={() => handleDeletePoll(poll.id)}
                            className="bg-red-600 text-white px-3 py-2 rounded text-xs sm:text-sm hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {polls.length === 0 && (
                  <p className="text-gray-600">No polls found.</p>
                )}
              </div>
            )}

            {activeTab === 'votes' && (
              <div>
                <h2 className="text-lg sm:text-xl font-semibold mb-4 sm:mb-6">Vote Management</h2>
                <div className="space-y-4">
                  {votes.map((vote) => (
                    <div key={vote.id} className="bg-white border rounded-lg p-4">
                      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium text-gray-900 text-sm sm:text-base">Poll ID: {vote.poll_id?.substring(0, 8)}...</h4>
                          <p className="text-xs sm:text-sm text-gray-600">User ID: {vote.user_id?.substring(0, 8)}...</p>
                          <p className="text-xs sm:text-sm text-gray-700">Selected: {vote.option_selected}</p>
                          <p className="text-xs sm:text-sm text-gray-500">
                            Voted: {new Date(vote.created_at).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="flex flex-col sm:flex-row gap-2 sm:space-x-2">
                          <button
                            onClick={() => handleDeleteVote(vote.id)}
                            className="bg-red-600 text-white px-3 py-2 rounded text-xs sm:text-sm hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {votes.length === 0 && (
                  <p className="text-gray-600">No votes found.</p>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  const location = useLocation();
  
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
    // Save the attempted location for redirect after login
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  
  return children;
};

// Dashboard Component
const Dashboard = () => {
  const { user } = useAuth();
  const { currentCourse } = useCourse();
  
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  
  // Moderators don't need course selection
  if (user.role === 'moderator') {
    return <ModeratorDashboard />;
  }
  
  // For students and professors, show course selection if no course is selected
  if (!currentCourse) {
    return <CourseSelection />;
  }
  
  // Show role-specific dashboard within the selected course
  if (user.role === 'student') {
    return <StudentDashboard />;
  } else if (user.role === 'professor') {
    return <ProfessorDashboard />;
  }
  
  return <Navigate to="/login" replace />;
};

// Main App Component
function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <CourseProvider>
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
              <Route 
                path="/dashboard" 
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } 
              />
              {/* Handle all other routes by redirecting to home */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Router>
        </CourseProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;