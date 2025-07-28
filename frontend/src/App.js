import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Temporary fix - hardcode the correct URL
const BACKEND_URL = 'https://zero1-classroom-1.onrender.com';
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sessionId] = useState(() => `session_${Date.now()}_${Math.random()}`);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    if (token && userData) {
      setUser(JSON.parse(userData));
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    try {
      const response = await axios.post(`${API}/login`, { 
        username, 
        password,
        session_id: sessionId  // Add session identifier
      });
      const { access_token, user: userData } = response.data;
      
      localStorage.setItem('token', access_token);
      localStorage.setItem('user', JSON.stringify(userData));
      localStorage.setItem('session_id', sessionId);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Login failed' };
    }
  };

  const register = async (username, email, password) => {
    try {
      const response = await axios.post(`${API}/register`, { username, email, password });
      const { access_token, user: userData } = response.data;
      
      localStorage.setItem('token', access_token);
      localStorage.setItem('user', JSON.stringify(userData));
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Registration failed' };
    }
  };

  const logout = async () => {
    try {
      // Call logout endpoint to remove server-side session
      await axios.post(`${API}/logout`);
    } catch (error) {
      console.error('Logout error:', error);
    }
    
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('session_id');
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

// Components
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
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex flex-row items-center justify-center gap-3 mb-2">
            <img src={process.env.PUBLIC_URL + '/Untitled_design__2_-removebg-preview.png'} alt="Classroom Logo" style={{ width: 56, height: 56 }} />
            <span className="text-3xl font-bold text-gray-900">Classroom</span>
          </div>
          {/* <h1 className="text-3xl font-bold text-gray-900 mb-2">Welcome Back</h1> */}
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

        {/* <div className="mt-6 p-4 bg-gray-50 rounded-lg">
          <p className="text-sm text-gray-600 mb-2">Professor Login:</p>
          <p className="text-xs text-gray-500">Username: professor60201</p>
          <p className="text-xs text-gray-500">Password: 60201professor</p>
        </div>

        <div className="mt-4 p-4 bg-yellow-50 rounded-lg">
          <p className="text-sm text-gray-600 mb-2">Moderator Login:</p>
          <p className="text-xs text-gray-500">Username: pepper_moderator</p>
          <p className="text-xs text-gray-500">Password: pepper_14627912</p>
        </div> */}
      </div>
    </div>
  );
};

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
          <div className=" text-gray-500 mb-2">Create Account</div>
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

const StudentDashboard = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('questions');
  const [questions, setQuestions] = useState([]);
  const [myQuestions, setMyQuestions] = useState([]);
  const [polls, setPolls] = useState([]);
  const [loading, setLoading] = useState(false);

  // Question form state
  const [questionText, setQuestionText] = useState('');
  const [isAnonymous, setIsAnonymous] = useState(false);
  const [editingQuestion, setEditingQuestion] = useState(null);

  useEffect(() => {
    fetchQuestions();
    fetchMyQuestions();
    fetchPolls();
  }, []);

  const fetchQuestions = async () => {
    try {
      const response = await axios.get(`${API}/questions`);
      setQuestions(response.data);
    } catch (error) {
      console.error('Error fetching questions:', error);
    }
  };

  const fetchMyQuestions = async () => {
    try {
      const response = await axios.get(`${API}/questions/my`);
      setMyQuestions(response.data);
    } catch (error) {
      console.error('Error fetching my questions:', error);
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

  const handleSubmitQuestion = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (editingQuestion) {
        await axios.put(`${API}/questions/${editingQuestion.id}`, {
          question_text: questionText
        });
        setEditingQuestion(null);
      } else {
        await axios.post(`${API}/questions`, {
          question_text: questionText,
          is_anonymous: isAnonymous
        });
      }
      
      setQuestionText('');
      setIsAnonymous(false);
      fetchQuestions();
      fetchMyQuestions();
    } catch (error) {
      console.error('Error submitting question:', error);
    }
    setLoading(false);
  };

  const handleEditQuestion = (question) => {
    setEditingQuestion(question);
    setQuestionText(question.question_text);
    setIsAnonymous(question.is_anonymous);
  };

  const handleDeleteQuestion = async (questionId) => {
    try {
      await axios.delete(`${API}/questions/${questionId}`);
      fetchQuestions();
      fetchMyQuestions();
    } catch (error) {
      console.error('Error deleting question:', error);
    }
  };

  const handleMarkAsAnswered = async (questionId) => {
    try {
      await axios.put(`${API}/questions/${questionId}`, {
        is_answered: true
      });
      fetchQuestions();
      fetchMyQuestions();
    } catch (error) {
      console.error('Error marking question as answered:', error);
    }
  };

  const handleVote = async (pollId, option) => {
    try {
      await axios.post(`${API}/polls/${pollId}/vote`, {
        poll_id: pollId,
        option_selected: option
      });
      fetchPolls();
    } catch (error) {
      console.error('Error voting:', error);
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
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <img src={process.env.PUBLIC_URL + '/Untitled_design__2_-removebg-preview.png'} alt="Classroom Logo" style={{ width: 36, height: 36, marginRight: 8 }} />
              <h1 className="text-2xl font-bold text-gray-900">Classroom</h1>
              <span className="ml-3 px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
                Student
              </span>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Hello, {user.username}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white rounded-lg shadow-sm mb-8">
          <div className="border-b">
            <nav className="flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab('questions')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'questions'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Ask Questions
              </button>
              <button
                onClick={() => setActiveTab('forum')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'forum'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Global Forum
              </button>
              <button
                onClick={() => setActiveTab('polls')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'polls'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Polls
              </button>
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'questions' && (
              <div className="space-y-8">
                <div className="bg-gray-50 rounded-lg p-6">
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
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'forum' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Global Questions Forum</h2>
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
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const PollCard = ({ poll, onVote }) => {
  const [userVote, setUserVote] = useState(null);
  const [hasVoted, setHasVoted] = useState(false);

  useEffect(() => {
    checkUserVote();
  }, [poll.id]);

  const checkUserVote = async () => {
    try {
      const response = await axios.get(`${API}/polls/${poll.id}/user-vote`);
      setHasVoted(response.data.voted);
      setUserVote(response.data.option);
    } catch (error) {
      console.error('Error checking user vote:', error);
    }
  };

  const handleVote = async (option) => {
    await onVote(poll.id, option);
    setHasVoted(true);
    setUserVote(option);
  };

  return (
    <div className="bg-white border rounded-lg p-6">
      <h3 className="text-lg font-semibold mb-4">{poll.question}</h3>
      <div className="space-y-3">
        {poll.options.map((option, index) => (
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
        ))}
      </div>
      <div className="mt-4 text-sm text-gray-500">
        Created: {new Date(poll.created_at).toLocaleDateString()}
      </div>
    </div>
  );
};

const ProfessorDashboard = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('questions');
  const [questions, setQuestions] = useState([]);
  const [polls, setPolls] = useState([]);
  const [loading, setLoading] = useState(false);

  // Poll form state
  const [pollQuestion, setPollQuestion] = useState('');
  const [pollOptions, setPollOptions] = useState(['', '']);

  useEffect(() => {
    fetchQuestions();
    fetchPolls();
  }, []);

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

  const handleMarkAsAnswered = async (questionId) => {
    try {
      await axios.put(`${API}/questions/${questionId}`, {
        is_answered: true
      });
      fetchQuestions();
    } catch (error) {
      console.error('Error marking question as answered:', error);
    }
  };

  const handleCreatePoll = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post(`${API}/polls`, {
        question: pollQuestion,
        options: pollOptions.filter(option => option.trim() !== '')
      });
      
      setPollQuestion('');
      setPollOptions(['', '']);
      fetchPolls();
    } catch (error) {
      console.error('Error creating poll:', error);
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

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <img src={process.env.PUBLIC_URL + '/Untitled_design__2_-removebg-preview.png'} alt="Classroom Logo" style={{ width: 36, height: 36, marginRight: 8 }} />
              <h1 className="text-2xl font-bold text-gray-900">Classroom</h1>
              <span className="ml-3 px-3 py-1 bg-purple-100 text-purple-800 rounded-full text-sm font-medium">
                Professor
              </span>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Hello, {user.username}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white rounded-lg shadow-sm mb-8">
          <div className="border-b">
            <nav className="flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab('questions')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'questions'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Questions Forum
              </button>
              <button
                onClick={() => setActiveTab('polls')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'polls'
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                Polls
              </button>
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'questions' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Questions Forum</h2>
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
                      <ProfessorPollCard key={poll.id} poll={poll} onDelete={fetchPolls} />
                    ))}
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

const ProfessorPollCard = ({ poll, onDelete }) => {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    fetchResults();
  }, [poll.id]);

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

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete this poll and all its votes?')) {
      try {
        await axios.delete(`${API}/polls/${poll.id}`);
        if (onDelete) onDelete();
      } catch (error) {
        alert('Error deleting poll: ' + (error.response?.data?.detail || error.message));
      }
    }
  };

  if (loading) {
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
        {results && results.poll.options.map((option, index) => {
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
        })}
      </div>
      <div className="mt-4 text-sm text-gray-500">
        <span>Total votes: {results?.total_votes || 0}</span>
        <span className="ml-4">Created: {new Date(poll.created_at).toLocaleDateString()}</span>
      </div>
      {/* Show delete button only if user is the creator */}
      {user && poll.created_by === user.id && (
        <button
          onClick={handleDelete}
          className="mt-4 bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700"
        >
          Delete
        </button>
      )}
    </div>
  );
};

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

const ModeratorDashboard = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({});
  const [users, setUsers] = useState([]);
  const [questions, setQuestions] = useState([]);
  const [polls, setPolls] = useState([]);
  const [votes, setVotes] = useState([]);

  useEffect(() => {
    fetchStats();
    fetchUsers();
    fetchQuestions();
    fetchPolls();
    fetchVotes();
  }, []);

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
        fetchUsers();
        fetchStats();
      } catch (error) {
        console.error('Error deleting user:', error);
      }
    }
  };

  const handleDeleteQuestion = async (questionId) => {
    if (window.confirm('Are you sure you want to delete this question?')) {
      try {
        await axios.delete(`${API}/admin/questions/${questionId}`);
        fetchQuestions();
        fetchStats();
      } catch (error) {
        console.error('Error deleting question:', error);
      }
    }
  };

  const handleDeletePoll = async (pollId) => {
    if (window.confirm('Are you sure you want to delete this poll and all its votes?')) {
      try {
        await axios.delete(`${API}/admin/polls/${pollId}`);
        fetchPolls();
        fetchVotes();
        fetchStats();
      } catch (error) {
        console.error('Error deleting poll:', error);
      }
    }
  };

  const handleDeleteVote = async (voteId) => {
    if (window.confirm('Are you sure you want to delete this vote?')) {
      try {
        await axios.delete(`${API}/admin/votes/${voteId}`);
        fetchVotes();
        fetchStats();
      } catch (error) {
        console.error('Error deleting vote:', error);
      }
    }
  };

  const handleToggleQuestionStatus = async (questionId, currentStatus) => {
    try {
      await axios.put(`${API}/admin/questions/${questionId}`, {
        is_answered: !currentStatus
      });
      fetchQuestions();
      fetchStats();
    } catch (error) {
      console.error('Error updating question status:', error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <img src={process.env.PUBLIC_URL + '/Untitled_design__2_-removebg-preview.png'} alt="Classroom Logo" style={{ width: 36, height: 36, marginRight: 8 }} />
              <h1 className="text-2xl font-bold text-gray-900">Classroom</h1>
              <span className="ml-3 px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm font-medium">
                Moderator
              </span>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Hello, {user.username}!</span>
              <button
                onClick={logout}
                className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white rounded-lg shadow-sm mb-8">
          <div className="border-b">
            <nav className="flex space-x-8 px-6">
              {['overview', 'users', 'questions', 'polls', 'votes'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`py-4 px-1 border-b-2 font-medium text-sm capitalize ${
                    activeTab === tab
                      ? 'border-red-500 text-red-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'overview' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">System Overview</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="bg-blue-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-blue-900">Total Users</h3>
                    <p className="text-3xl font-bold text-blue-600">{stats.total_users || 0}</p>
                    <p className="text-sm text-blue-700">
                      Students: {stats.students || 0} | Professors: {stats.professors || 0} | Moderators: {stats.moderators || 0}
                    </p>
                  </div>
                  <div className="bg-green-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-green-900">Questions</h3>
                    <p className="text-3xl font-bold text-green-600">{stats.total_questions || 0}</p>
                    <p className="text-sm text-green-700">
                      Answered: {stats.answered_questions || 0} | Unanswered: {stats.unanswered_questions || 0}
                    </p>
                  </div>
                  <div className="bg-purple-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-purple-900">Polls</h3>
                    <p className="text-3xl font-bold text-purple-600">{stats.total_polls || 0}</p>
                  </div>
                  <div className="bg-orange-50 p-6 rounded-lg">
                    <h3 className="text-lg font-medium text-orange-900">Votes</h3>
                    <p className="text-3xl font-bold text-orange-600">{stats.total_votes || 0}</p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'users' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">User Management</h2>
                <div className="space-y-4">
                  {users.map((user) => (
                    <div key={user.id} className="bg-white border rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <div>
                          <h4 className="font-medium text-gray-900">{user.username}</h4>
                          <p className="text-sm text-gray-600">{user.email}</p>
                          <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium mt-2 ${
                            user.role === 'student' ? 'bg-blue-100 text-blue-800' :
                            user.role === 'professor' ? 'bg-purple-100 text-purple-800' :
                            'bg-red-100 text-red-800'
                          }`}>
                            {user.role}
                          </span>
                        </div>
                        <div className="flex space-x-2">
                          <button
                            onClick={() => handleDeleteUser(user.id)}
                            disabled={user.role === 'moderator'}
                            className={`px-3 py-1 text-sm rounded ${
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
              </div>
            )}

            {activeTab === 'questions' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Question Management</h2>
                <div className="space-y-4">
                  {questions.map((question) => (
                    <div key={question.id} className="bg-white border rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <h4 className="font-medium text-gray-900">{question.question_text}</h4>
                          <div className="flex items-center space-x-4 text-sm text-gray-500 mt-2">
                            <span>By: {question.username}</span>
                            <span>{new Date(question.created_at).toLocaleDateString()}</span>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              question.is_answered ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                            }`}>
                              {question.is_answered ? 'Answered' : 'Unanswered'}
                            </span>
                          </div>
                        </div>
                        <div className="flex space-x-2">
                          <button
                            onClick={() => handleToggleQuestionStatus(question.id, question.is_answered)}
                            className={`px-3 py-1 text-sm rounded ${
                              question.is_answered
                                ? 'bg-yellow-600 text-white hover:bg-yellow-700'
                                : 'bg-green-600 text-white hover:bg-green-700'
                            }`}
                          >
                            {question.is_answered ? 'Mark Unanswered' : 'Mark Answered'}
                          </button>
                          <button
                            onClick={() => handleDeleteQuestion(question.id)}
                            className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'polls' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Poll Management</h2>
                <div className="space-y-4">
                  {polls.map((poll) => (
                    <div key={poll.id} className="bg-white border rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <h4 className="font-medium text-gray-900">{poll.question}</h4>
                          <div className="mt-2">
                            <p className="text-sm text-gray-600">Options:</p>
                            <ul className="list-disc list-inside text-sm text-gray-700 mt-1">
                              {poll.options.map((option, index) => (
                                <li key={index}>{option}</li>
                              ))}
                            </ul>
                          </div>
                          <p className="text-sm text-gray-500 mt-2">
                            Created: {new Date(poll.created_at).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="flex space-x-2">
                          <button
                            onClick={() => handleDeletePoll(poll.id)}
                            className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'votes' && (
              <div>
                <h2 className="text-xl font-semibold mb-6">Vote Management</h2>
                <div className="space-y-4">
                  {votes.map((vote) => (
                    <div key={vote.id} className="bg-white border rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <div>
                          <h4 className="font-medium text-gray-900">Poll ID: {vote.poll_id.substring(0, 8)}...</h4>
                          <p className="text-sm text-gray-600">User ID: {vote.user_id.substring(0, 8)}...</p>
                          <p className="text-sm text-gray-700">Selected: {vote.option_selected}</p>
                          <p className="text-sm text-gray-500">
                            Voted: {new Date(vote.created_at).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="flex space-x-2">
                          <button
                            onClick={() => handleDeleteVote(vote.id)}
                            className="bg-red-600 text-white px-3 py-1 rounded text-sm hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

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

export default App;