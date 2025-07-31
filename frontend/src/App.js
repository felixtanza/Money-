import React, { useState, useEffect, createContext, useContext } from 'react';
import { LogIn, UserPlus, Home, List, DollarSign, Bell, Settings, Wallet, RefreshCcw, CheckCircle, XCircle, Loader2, Users, Send, FileText, LayoutDashboard } from 'lucide-react'; // Importing new icons for admin panel

// --- Context for User and Authentication State ---
const AuthContext = createContext(null);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token')); // Load token from local storage
  const [loading, setLoading] = useState(true); // Initial loading state for auth check
  const [error, setError] = useState(null);

  // Fix: Use window.__backend_url if available, fallback to process.env, then localhost
  // This resolves the "ReferenceError: process is not defined" in browser environments.
  const BACKEND_URL = window.__backend_url || process.env.REACT_APP_BACKEND_URL || 'http://localhost:8000';

  // Function to fetch current user data
  const fetchCurrentUser = async (authToken) => {
    if (!authToken) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const response = await fetch(`${BACKEND_URL}/api/dashboard/stats`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
      });
      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
        setError(null);
      } else if (response.status === 401) {
        // Token expired or invalid, clear it
        logout();
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Failed to fetch user data.');
        setUser(null);
      }
    } catch (err) {
      console.error('Error fetching current user:', err);
      setError('Network error or unable to connect to backend.');
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  // Login function
  const login = async (username, password) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('token', data.token); // Store token
        setToken(data.token);
        setUser(data.user);
        return { success: true, message: data.message };
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Login failed.');
        return { success: false, message: errorData.detail || 'Login failed.' };
      }
    } catch (err) {
      console.error('Login error:', err);
      setError('Network error or unable to connect to backend.');
      return { success: false, message: 'Network error or unable to connect to backend.' };
    } finally {
      setLoading(false);
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setError(null);
    setLoading(false);
  };

  // Initial check on component mount
  useEffect(() => {
    fetchCurrentUser(token);
  }, [token]); // Re-fetch if token changes

  const authContextValue = { user, token, loading, error, login, logout, fetchCurrentUser, BACKEND_URL };

  return (
    <AuthContext.Provider value={authContextValue}>
      {children}
    </AuthContext.Provider>
  );
};

// --- Main App Component ---
function App() {
  const { user, token, loading, error, logout } = useContext(AuthContext);
  const [currentPage, setCurrentPage] = useState('home'); // 'home', 'tasks', 'payments', 'notifications', 'settings', 'admin'

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
        <Loader2 className="animate-spin h-10 w-10 text-blue-500" />
        <p className="ml-3 text-lg">Loading application...</p>
      </div>
    );
  }

  if (!user && currentPage !== 'register') {
    return <AuthPage setCurrentPage={setCurrentPage} />;
  }

  return (
    <div className={`min-h-screen flex flex-col ${user?.theme === 'dark' ? 'dark bg-gray-900 text-gray-100' : 'bg-gray-100 text-gray-900'}`}>
      <Navbar currentPage={currentPage} setCurrentPage={setCurrentPage} user={user} logout={logout} />
      <main className="flex-grow p-4 md:p-8">
        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative mb-4" role="alert">
            <strong className="font-bold">Error!</strong>
            <span className="block sm:inline ml-2">{error}</span>
          </div>
        )}
        {currentPage === 'home' && <DashboardPage />}
        {currentPage === 'tasks' && <TasksPage />}
        {currentPage === 'payments' && <PaymentsPage />}
        {currentPage === 'notifications' && <NotificationsPage />}
        {currentPage === 'settings' && <SettingsPage />}
        {currentPage === 'admin' && user?.role === 'admin' && <AdminPage />} {/* Render AdminPage only for admins */}
        {currentPage === 'register' && <RegisterPage setCurrentPage={setCurrentPage} />}
      </main>
    </div>
  );
}

// --- Navbar Component ---
const Navbar = ({ currentPage, setCurrentPage, user, logout }) => {
  return (
    <nav className="bg-white dark:bg-gray-800 shadow-md p-4 flex justify-between items-center rounded-b-lg">
      <h1 className="text-2xl font-bold text-blue-600 dark:text-blue-400">EarnPlatform</h1>
      <div className="flex items-center space-x-4">
        <span className="text-lg font-medium hidden md:block">Welcome, {user?.username || 'Guest'}</span>
        <button
          onClick={() => setCurrentPage('home')}
          className={`px-3 py-2 rounded-md text-sm font-medium ${currentPage === 'home' ? 'bg-blue-500 text-white' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'}`}
        >
          <Home className="inline-block mr-1" size={18} /> Home
        </button>
        <button
          onClick={() => setCurrentPage('tasks')}
          className={`px-3 py-2 rounded-md text-sm font-medium ${currentPage === 'tasks' ? 'bg-blue-500 text-white' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'}`}
        >
          <List className="inline-block mr-1" size={18} /> Tasks
        </button>
        <button
          onClick={() => setCurrentPage('payments')}
          className={`px-3 py-2 rounded-md text-sm font-medium ${currentPage === 'payments' ? 'bg-blue-500 text-white' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'}`}
        >
          <DollarSign className="inline-block mr-1" size={18} /> Payments
        </button>
        <button
          onClick={() => setCurrentPage('notifications')}
          className={`px-3 py-2 rounded-md text-sm font-medium ${currentPage === 'notifications' ? 'bg-blue-500 text-white' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'}`}
        >
          <Bell className="inline-block mr-1" size={18} /> Notifications
        </button>
        {user?.role === 'admin' && ( // Only show Admin Panel for admin users
          <button
            onClick={() => setCurrentPage('admin')}
            className={`px-3 py-2 rounded-md text-sm font-medium ${currentPage === 'admin' ? 'bg-blue-500 text-white' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'}`}
          >
            <LayoutDashboard className="inline-block mr-1" size={18} /> Admin Panel
          </button>
        )}
        <button
          onClick={() => setCurrentPage('settings')}
          className={`px-3 py-2 rounded-md text-sm font-medium ${currentPage === 'settings' ? 'bg-blue-500 text-white' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'}`}
        >
          <Settings className="inline-block mr-1" size={18} /> Settings
        </button>
        <button
          onClick={logout}
          className="px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 transition duration-200 text-sm font-medium"
        >
          <LogIn className="inline-block mr-1" size={18} /> Logout
        </button>
      </div>
    </nav>
  );
};

// --- AuthPage (Login/Register Switch) ---
const AuthPage = ({ setCurrentPage }) => {
  const [isLogin, setIsLogin] = useState(true);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      <div className="bg-white dark:bg-gray-800 p-8 rounded-lg shadow-xl w-full max-w-md">
        <h2 className="text-3xl font-bold text-center mb-6 text-blue-600 dark:text-blue-400">
          {isLogin ? 'Login' : 'Register'}
        </h2>
        {isLogin ? <LoginForm /> : <RegisterForm setIsLogin={setIsLogin} />}
        <p className="text-center mt-6 text-gray-600 dark:text-gray-400">
          {isLogin ? "Don't have an account?" : "Already have an account?"}{' '}
          <button
            onClick={() => setIsLogin(!isLogin)}
            className="text-blue-500 hover:underline font-medium"
          >
            {isLogin ? 'Register here' : 'Login here'}
          </button>
        </p>
      </div>
    </div>
  );
};

// --- LoginForm Component ---
const LoginForm = () => {
  const { login, error } = useContext(AuthContext);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    const result = await login(username, password);
    setMessage(result.message);
    setLoading(false);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Username</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 bg-gray-50 dark:bg-gray-700 dark:text-gray-100"
          required
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 bg-gray-50 dark:bg-gray-700 dark:text-gray-100"
          required
        />
      </div>
      {message && (
        <div className={`text-sm ${error ? 'text-red-600' : 'text-green-600'} text-center`}>
          {message}
        </div>
      )}
      <button
        type="submit"
        className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition duration-200 flex items-center justify-center"
        disabled={loading}
      >
        {loading && <Loader2 className="animate-spin h-5 w-5 mr-2" />}
        Login
      </button>
    </form>
  );
};

// --- RegisterForm Component ---
const RegisterForm = ({ setIsLogin }) => {
  const { BACKEND_URL } = useContext(AuthContext);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    full_name: '',
    phone: '',
    referral_code: '',
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setIsError(false);

    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage(data.message + " Please log in.");
        setIsError(false);
        // Optionally, automatically switch to login form after successful registration
        setTimeout(() => setIsLogin(true), 2000);
      } else {
        setMessage(data.detail || 'Registration failed.');
        setIsError(true);
      }
    } catch (err) {
      console.error('Registration error:', err);
      setMessage('Network error or unable to connect to backend.');
      setIsError(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Username</label>
        <input type="text" name="username" value={formData.username} onChange={handleChange} className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100" required />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Email</label>
        <input type="email" name="email" value={formData.email} onChange={handleChange} className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100" required />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Password</label>
        <input type="password" name="password" value={formData.password} onChange={handleChange} className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100" required />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Full Name</label>
        <input type="text" name="full_name" value={formData.full_name} onChange={handleChange} className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100" required />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Phone (e.g., 254712345678)</label>
        <input type="text" name="phone" value={formData.phone} onChange={handleChange} className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100" required pattern="^254\d{9}$" title="Phone number must be in 254XXXXXXXXX format" />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Referral Code (Optional)</label>
        <input type="text" name="referral_code" value={formData.referral_code} onChange={handleChange} className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100" />
      </div>
      {message && (
        <div className={`text-sm ${isError ? 'text-red-600' : 'text-green-600'} text-center`}>
          {message}
        </div>
      )}
      <button
        type="submit"
        className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition duration-200 flex items-center justify-center"
        disabled={loading}
      >
        {loading && <Loader2 className="animate-spin h-5 w-5 mr-2" />}
        Register
      </button>
    </form>
  );
};

// --- DashboardPage Component ---
const DashboardPage = () => {
  const { user, token, BACKEND_URL, fetchCurrentUser } = useContext(AuthContext);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [loadingStats, setLoadingStats] = useState(true);
  const [statsError, setStatsError] = useState(null);

  useEffect(() => {
    const getDashboardStats = async () => {
      if (!token) {
        setLoadingStats(false);
        return;
      }
      setLoadingStats(true);
      setStatsError(null);
      try {
        const response = await fetch(`${BACKEND_URL}/api/dashboard/stats`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });
        if (response.ok) {
          const data = await response.json();
          setDashboardStats(data);
        } else {
          const errorData = await response.json();
          setStatsError(errorData.detail || 'Failed to fetch dashboard stats.');
        }
      } catch (err) {
        console.error('Error fetching dashboard stats:', err);
        setStatsError('Network error while fetching dashboard stats.');
      } finally {
        setLoadingStats(false);
      }
    };
    getDashboardStats();
  }, [token, BACKEND_URL]);

  return (
    <div className="container mx-auto p-4 bg-white dark:bg-gray-800 rounded-lg shadow-md">
      <h2 className="text-3xl font-bold mb-6 text-blue-600 dark:text-blue-400">Dashboard</h2>
      {loadingStats ? (
        <div className="flex items-center justify-center p-4">
          <Loader2 className="animate-spin h-8 w-8 text-blue-500" />
          <p className="ml-3">Loading dashboard data...</p>
        </div>
      ) : statsError ? (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative">
          <strong className="font-bold">Error:</strong>
          <span className="block sm:inline ml-2">{statsError}</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <StatCard title="Wallet Balance" value={`KSH ${user?.wallet_balance?.toFixed(2) || '0.00'}`} icon={<Wallet className="h-6 w-6 text-blue-500" />} />
          <StatCard title="Total Earned" value={`KSH ${user?.total_earned?.toFixed(2) || '0.00'}`} icon={<DollarSign className="h-6 w-6 text-green-500" />} />
          <StatCard title="Total Withdrawn" value={`KSH ${user?.total_withdrawn?.toFixed(2) || '0.00'}`} icon={<RefreshCcw className="h-6 w-6 text-orange-500" />} />
          <StatCard title="Tasks Completed" value={dashboardStats?.task_completions || 0} icon={<CheckCircle className="h-6 w-6 text-purple-500" />} />
          <StatCard title="Referrals" value={dashboardStats?.referral_stats?.total_referred || 0} icon={<UserPlus className="h-6 w-6 text-pink-500" />} />
          <StatCard title="Referral Earnings" value={`KSH ${dashboardStats?.referral_stats?.total_referral_earnings?.toFixed(2) || '0.00'}`} icon={<DollarSign className="h-6 w-6 text-yellow-500" />} />
          
          <div className="lg:col-span-3 bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-inner">
            <h3 className="text-xl font-semibold mb-4 text-gray-800 dark:text-gray-200">Account Status</h3>
            <p className="text-lg">
              Status: <span className={`font-bold ${user?.is_activated ? 'text-green-500' : 'text-red-500'}`}>
                {user?.is_activated ? 'Activated' : 'Inactive'}
              </span>
            </p>
            {!user?.is_activated && (
              <p className="text-md mt-2 text-gray-600 dark:text-gray-400">
                Deposit KSH {user?.activation_amount?.toFixed(2) || '500.00'} to activate your account and unlock tasks.
              </p>
            )}
            <p className="text-md mt-2 text-gray-600 dark:text-gray-400">
              Your Referral Code: <span className="font-mono text-blue-500 dark:text-blue-300">{user?.referral_code}</span>
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

// --- StatCard Component (Helper for Dashboard) ---
const StatCard = ({ title, value, icon }) => (
  <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-md flex items-center space-x-4">
    <div className="p-3 bg-blue-100 dark:bg-blue-900 rounded-full">
      {icon}
    </div>
    <div>
      <h3 className="text-md font-medium text-gray-600 dark:text-gray-400">{title}</h3>
      <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{value}</p>
    </div>
  </div>
);

// --- TasksPage Component ---
const TasksPage = () => {
  const { user, token, BACKEND_URL, fetchCurrentUser } = useContext(AuthContext);
  const [tasks, setTasks] = useState([]);
  const [loadingTasks, setLoadingTasks] = useState(true);
  const [tasksError, setTasksError] = useState(null);
  const [submissionMessage, setSubmissionMessage] = useState('');
  const [submissionError, setSubmissionError] = useState(false);

  useEffect(() => {
    const fetchTasks = async () => {
      if (!token) {
        setLoadingTasks(false);
        return;
      }
      setLoadingTasks(true);
      setTasksError(null);
      try {
        const response = await fetch(`${BACKEND_URL}/api/tasks`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });
        if (response.ok) {
          const data = await response.json();
          setTasks(data.tasks);
        } else {
          const errorData = await response.json();
          setTasksError(errorData.detail || 'Failed to fetch tasks.');
        }
      } catch (err) {
        console.error('Error fetching tasks:', err);
        setTasksError('Network error while fetching tasks.');
      } finally {
        setLoadingTasks(false);
      }
    };
    fetchTasks();
  }, [token, BACKEND_URL, submissionMessage]); // Re-fetch tasks after a submission

  const handleTaskSubmit = async (taskId, completionData) => {
    setSubmissionMessage('');
    setSubmissionError(false);
    try {
      const response = await fetch(`${BACKEND_URL}/api/tasks/complete`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ task_id: taskId, completion_data: completionData }),
      });

      const data = await response.json();
      if (response.ok) {
        setSubmissionMessage(data.message);
        setSubmissionError(false);
        fetchCurrentUser(token); // Update user balance/status after task completion
      } else {
        setSubmissionMessage(data.detail || 'Task submission failed.');
        setSubmissionError(true);
      }
    } catch (err) {
      console.error('Error submitting task:', err);
      setSubmissionMessage('Network error or unable to connect to backend for task submission.');
      setSubmissionError(true);
    }
  };

  if (!user?.is_activated) {
    return (
      <div className="container mx-auto p-8 bg-white dark:bg-gray-800 rounded-lg shadow-md text-center">
        <h2 className="text-3xl font-bold mb-4 text-red-600 dark:text-red-400">Account Inactive</h2>
        <p className="text-lg text-gray-700 dark:text-gray-300">
          Your account is not activated. Please deposit KSH {user?.activation_amount?.toFixed(2) || '500.00'} to activate and access tasks.
        </p>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-4 bg-white dark:bg-gray-800 rounded-lg shadow-md">
      <h2 className="text-3xl font-bold mb-6 text-blue-600 dark:text-blue-400">Available Tasks</h2>
      {submissionMessage && (
        <div className={`px-4 py-3 rounded-lg relative mb-4 ${submissionError ? 'bg-red-100 border border-red-400 text-red-700' : 'bg-green-100 border border-green-400 text-green-700'}`} role="alert">
          <strong className="font-bold">{submissionError ? 'Error!' : 'Success!'}</strong>
          <span className="block sm:inline ml-2">{submissionMessage}</span>
        </div>
      )}
      {loadingTasks ? (
        <div className="flex items-center justify-center p-4">
          <Loader2 className="animate-spin h-8 w-8 text-blue-500" />
          <p className="ml-3">Loading tasks...</p>
        </div>
      ) : tasksError ? (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative">
          <strong className="font-bold">Error:</strong>
          <span className="block sm:inline ml-2">{tasksError}</span>
        </div>
      ) : tasks.length === 0 ? (
        <p className="text-lg text-gray-600 dark:text-gray-400">No tasks available at the moment. Check back later!</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {tasks.map((task) => (
            <TaskCard key={task.task_id} task={task} onTaskSubmit={handleTaskSubmit} />
          ))}
        </div>
      )}
    </div>
  );
};

// --- TaskCard Component (Helper for TasksPage) ---
const TaskCard = ({ task, onTaskSubmit }) => {
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({});
  const [loading, setLoading] = useState(false);

  const handleFormChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await onTaskSubmit(task.task_id, formData);
    setLoading(false);
    setShowForm(false); // Hide form after submission attempt
    setFormData({}); // Clear form data
  };

  return (
    <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-md">
      <h3 className="text-xl font-semibold text-blue-600 dark:text-blue-400 mb-2">{task.title}</h3>
      <p className="text-gray-700 dark:text-gray-300 mb-2">{task.description}</p>
      <p className="text-lg font-bold text-green-600 dark:text-green-400 mb-4">Reward: KSH {task.reward.toFixed(2)}</p>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">Type: {task.type}</p>

      {!showForm ? (
        <button
          onClick={() => setShowForm(true)}
          className="w-full bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600 transition duration-200 flex items-center justify-center"
        >
          Complete Task
        </button>
      ) : (
        <form onSubmit={handleFormSubmit} className="mt-4 space-y-3">
          {task.requirements.map((req, index) => (
            <div key={index}>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                {req.label} {req.required && <span className="text-red-500">*</span>}
              </label>
              {req.type === 'text' && (
                <input
                  type="text"
                  name={req.field_name}
                  value={formData[req.field_name] || ''}
                  onChange={handleFormChange}
                  className="w-full px-3 py-2 border rounded-md bg-gray-100 dark:bg-gray-600 dark:text-gray-100"
                  required={req.required}
                />
              )}
              {req.type === 'number' && (
                <input
                  type="number"
                  name={req.field_name}
                  value={formData[req.field_name] || ''}
                  onChange={handleFormChange}
                  className="w-full px-3 py-2 border rounded-md bg-gray-100 dark:bg-gray-600 dark:text-gray-100"
                  required={req.required}
                  min={req.min}
                  max={req.max}
                />
              )}
              {/* Add more input types as needed (e.g., 'textarea', 'checkbox', 'select') */}
            </div>
          ))}
          <div className="flex space-x-2">
            <button
              type="submit"
              className="flex-1 bg-green-500 text-white py-2 px-4 rounded-md hover:bg-green-600 transition duration-200 flex items-center justify-center"
              disabled={loading}
            >
              {loading && <Loader2 className="animate-spin h-5 w-5 mr-2" />}
              Submit
            </button>
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="flex-1 bg-gray-400 text-white py-2 px-4 rounded-md hover:bg-gray-500 transition duration-200"
              disabled={loading}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

// --- PaymentsPage Component ---
const PaymentsPage = () => {
  const { user, token, BACKEND_URL, fetchCurrentUser } = useContext(AuthContext);
  const [amount, setAmount] = useState('');
  const [phone, setPhone] = useState(user?.phone || '');
  const [paymentType, setPaymentType] = useState('deposit'); // 'deposit' or 'withdraw'
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);

  const handlePaymentSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setIsError(false);

    if (!token) {
      setMessage('You must be logged in to perform this action.');
      setIsError(true);
      setLoading(false);
      return;
    }

    const endpoint = paymentType === 'deposit' ? '/api/payments/deposit' : '/api/payments/withdraw';
    const payload = { amount: parseFloat(amount), phone };

    try {
      const response = await fetch(`${BACKEND_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setIsError(false);
        setAmount(''); // Clear amount after successful initiation
        fetchCurrentUser(token); // Refresh user data to show updated balance (if deposit was auto-approved or withdrawal deducted)
      } else {
        setMessage(data.detail || `Failed to ${paymentType}.`);
        setIsError(true);
      }
    } catch (err) {
      console.error(`Error during ${paymentType}:`, err);
      setMessage(`Network error or unable to connect to backend for ${paymentType}.`);
      setIsError(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto p-4 bg-white dark:bg-gray-800 rounded-lg shadow-md">
      <h2 className="text-3xl font-bold mb-6 text-blue-600 dark:text-blue-400">Payments</h2>
      <div className="mb-6 flex space-x-4">
        <button
          onClick={() => setPaymentType('deposit')}
          className={`px-6 py-3 rounded-lg font-semibold transition duration-200 ${paymentType === 'deposit' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
        >
          Deposit
        </button>
        <button
          onClick={() => setPaymentType('withdraw')}
          className={`px-6 py-3 rounded-lg font-semibold transition duration-200 ${paymentType === 'withdraw' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
        >
          Withdraw
        </button>
      </div>

      <form onSubmit={handlePaymentSubmit} className="space-y-4 max-w-md mx-auto">
        <h3 className="text-2xl font-semibold mb-4 text-gray-800 dark:text-gray-200 text-center">
          {paymentType === 'deposit' ? 'Make a Deposit' : 'Request a Withdrawal'}
        </h3>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Amount (KSH)</label>
          <input
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100"
            min="1"
            required
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Phone Number (e.g., 254712345678)</label>
          <input
            type="text"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            className="w-full px-4 py-2 border rounded-md bg-gray-50 dark:bg-gray-700 dark:text-gray-100"
            pattern="^254\d{9}$"
            title="Phone number must be in 254XXXXXXXXX format"
            required
          />
        </div>
        {message && (
          <div className={`text-sm ${isError ? 'text-red-600' : 'text-green-600'} text-center`}>
            {message}
          </div>
        )}
        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 transition duration-200 flex items-center justify-center font-semibold"
          disabled={loading}
        >
          {loading && <Loader2 className="animate-spin h-5 w-5 mr-2" />}
          {paymentType === 'deposit' ? 'Initiate Deposit' : 'Request Withdrawal'}
        </button>
      </form>
    </div>
  );
};

// --- NotificationsPage Component ---
const NotificationsPage = () => {
  const { token, BACKEND_URL } = useContext(AuthContext);
  const [notifications, setNotifications] = useState([]);
  const [loadingNotifications, setLoadingNotifications] = useState(true);
  const [notificationsError, setNotificationsError] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0); // To manually trigger refresh

  useEffect(() => {
    const fetchNotifications = async () => {
      if (!token) {
        setLoadingNotifications(false);
        return;
      }
      setLoadingNotifications(true);
      setNotificationsError(null);
      try {
        const response = await fetch(`${BACKEND_URL}/api/notifications`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });
        if (response.ok) {
          const data = await response.json();
          setNotifications(data.notifications);
        } else {
          const errorData = await response.json();
          setNotificationsError(errorData.detail || 'Failed to fetch notifications.');
        }
      } catch (err) {
        console.error('Error fetching notifications:', err);
        setNotificationsError('Network error while fetching notifications.');
      } finally {
        setLoadingNotifications(false);
      }
    };
    fetchNotifications();
  }, [token, BACKEND_URL, refreshTrigger]);

  const handleMarkAsRead = async (notificationId) => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/notifications/${notificationId}/read`, {
        method: 'POST', // Changed to POST as per backend
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      if (response.ok) {
        // Optimistically update UI or re-fetch
        setNotifications(prev => prev.map(n => n.notification_id === notificationId ? { ...n, read: true } : n));
        setRefreshTrigger(prev => prev + 1); // Trigger re-fetch to ensure consistency
      } else {
        const errorData = await response.json();
        // Using alert for simplicity, replace with custom modal in production
        alert(errorData.detail || 'Failed to mark notification as read.');
      }
    } catch (err) {
      console.error('Error marking notification as read:', err);
      // Using alert for simplicity, replace with custom modal in production
      alert('Network error marking notification as read.');
    }
  };

  return (
    <div className="container mx-auto p-4 bg-white dark:bg-gray-800 rounded-lg shadow-md">
      <h2 className="text-3xl font-bold mb-6 text-blue-600 dark:text-blue-400">Your Notifications</h2>
      {loadingNotifications ? (
        <div className="flex items-center justify-center p-4">
          <Loader2 className="animate-spin h-8 w-8 text-blue-500" />
          <p className="ml-3">Loading notifications...</p>
        </div>
      ) : notificationsError ? (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative">
          <strong className="font-bold">Error:</strong>
          <span className="block sm:inline ml-2">{notificationsError}</span>
        </div>
      ) : notifications.length === 0 ? (
        <p className="text-lg text-gray-600 dark:text-gray-400">No new notifications.</p>
      ) : (
        <div className="space-y-4">
          {notifications.map((notification) => (
            <div
              key={notification.notification_id}
              className={`p-4 rounded-lg shadow-sm flex items-center justify-between ${notification.read ? 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400' : 'bg-blue-50 dark:bg-blue-900 text-gray-900 dark:text-gray-100'}`}
            >
              <div>
                <h3 className="font-semibold text-lg flex items-center">
                  {notification.type === 'SUCCESS' && <CheckCircle className="h-5 w-5 mr-2 text-green-500" />}
                  {notification.type === 'ERROR' && <XCircle className="h-5 w-5 mr-2 text-red-500" />}
                  {notification.type === 'INFO' && <Bell className="h-5 w-5 mr-2 text-blue-500" />}
                  {notification.title}
                </h3>
                <p className="text-sm mt-1">{notification.message}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {new Date(notification.created_at).toLocaleString()}
                </p>
              </div>
              {!notification.read && (
                <button
                  onClick={() => handleMarkAsRead(notification.notification_id)}
                  className="bg-blue-500 text-white px-3 py-1 rounded-md text-sm hover:bg-blue-600 transition duration-200"
                >
                  Mark as Read
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// --- SettingsPage Component ---
const SettingsPage = () => {
  const { user, token, BACKEND_URL, fetchCurrentUser } = useContext(AuthContext);
  const [theme, setTheme] = useState(user?.theme || 'light');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);

  useEffect(() => {
    if (user) {
      setTheme(user.theme);
    }
  }, [user]);

  const handleThemeChange = async (newTheme) => {
    setLoading(true);
    setMessage('');
    setIsError(false);
    try {
      // Note: Backend's update_user_profile uses Form, so sending as FormData
      const formData = new FormData();
      formData.append('theme', newTheme);

      const response = await fetch(`${BACKEND_URL}/api/user/profile`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          // 'Content-Type': 'application/json', // Do NOT set Content-Type for FormData, browser sets it
        },
        body: formData, // Send as FormData
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setIsError(false);
        setTheme(newTheme);
        fetchCurrentUser(token); // Update global user state
      } else {
        setMessage(data.detail || 'Failed to update theme.');
        setIsError(true);
      }
    } catch (err) {
      console.error('Error updating theme:', err);
      setMessage('Network error or unable to connect to backend.');
      setIsError(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto p-4 bg-white dark:bg-gray-800 rounded-lg shadow-md">
      <h2 className="text-3xl font-bold mb-6 text-blue-600 dark:text-blue-400">Settings</h2>
      <div className="space-y-4">
        <div>
          <label className="block text-lg font-medium text-gray-700 dark:text-gray-300 mb-2">Theme</label>
          <div className="flex space-x-4">
            <button
              onClick={() => handleThemeChange('light')}
              className={`px-6 py-3 rounded-lg font-semibold transition duration-200 ${theme === 'light' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
              disabled={loading}
            >
              Light
            </button>
            <button
              onClick={() => handleThemeChange('dark')}
              className={`px-6 py-3 rounded-lg font-semibold transition duration-200 ${theme === 'dark' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
              disabled={loading}
            >
              Dark
            </button>
          </div>
        </div>
        {message && (
          <div className={`text-sm ${isError ? 'text-red-600' : 'text-green-600'} text-center`}>
            {message}
          </div>
        )}
        {loading && (
          <div className="flex items-center justify-center p-4">
            <Loader2 className="animate-spin h-6 w-6 text-blue-500" />
            <p className="ml-2">Updating settings...</p>
          </div>
        )}
      </div>
    </div>
  );
};

// --- AdminPage Component ---
const AdminPage = () => {
  const { user } = useContext(AuthContext);
  const [adminSection, setAdminSection] = useState('users'); // 'users', 'transactions', 'broadcast', 'submissions'

  if (user?.role !== 'admin') {
    return (
      <div className="container mx-auto p-8 bg-white dark:bg-gray-800 rounded-lg shadow-md text-center">
        <h2 className="text-3xl font-bold mb-4 text-red-600 dark:text-red-400">Access Denied</h2>
        <p className="text-lg text-gray-700 dark:text-gray-300">
          You do not have administrative privileges to access this page.
        </p>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-4 bg-white dark:bg-gray-800 rounded-lg shadow-md">
      <h2 className="text-3xl font-bold mb-6 text-blue-600 dark:text-blue-400">Admin Panel</h2>
      <div className="mb-6 flex flex-wrap gap-4">
        <button
          onClick={() => setAdminSection('users')}
          className={`px-4 py-2 rounded-lg font-semibold transition duration-200 flex items-center ${adminSection === 'users' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
        >
          <Users className="inline-block mr-2" size={18} /> User Management
        </button>
        <button
          onClick={() => setAdminSection('transactions')}
          className={`px-4 py-2 rounded-lg font-semibold transition duration-200 flex items-center ${adminSection === 'transactions' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
        >
          <DollarSign className="inline-block mr-2" size={18} /> All Transactions
        </button>
        <button
          onClick={() => setAdminSection('broadcast')}
          className={`px-4 py-2 rounded-lg font-semibold transition duration-200 flex items-center ${adminSection === 'broadcast' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
        >
          <Send className="inline-block mr-2" size={18} /> Broadcast Notification
        </button>
        <button
          onClick={() => setAdminSection('submissions')}
          className={`px-4 py-2 rounded-lg font-semibold transition duration-200 flex items-center ${adminSection === 'submissions' ? 'bg-blue-600 text-white shadow-lg' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600'}`}
        >
          <FileText className="inline-block mr-2" size={18} /> Task Submissions
        </button>
      </div>

      <div>
        {adminSection === 'users' && <UserManagement />}
        {adminSection === 'transactions' && <TransactionViewer />}
        {adminSection === 'broadcast' && <BroadcastNotificationSender />}
        {adminSection === 'submissions' && <TaskSubmissionReview />}
      </div>
    </div>
  );
};

// --- UserManagement Component (Admin) ---
const UserManagement = () => {
  const { token, BACKEND_URL } = useContext(AuthContext);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState('');
  const [isMessageError, setIsMessageError] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    const fetchUsers = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(`${BACKEND_URL}/api/admin/users`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (response.ok) {
          const data = await response.json();
          setUsers(data);
        } else {
          const errorData = await response.json();
          setError(errorData.detail || 'Failed to fetch users.');
        }
      } catch (err) {
        console.error('Error fetching users:', err);
        setError('Network error or unable to connect to backend.');
      } finally {
        setLoading(false);
      }
    };
    fetchUsers();
  }, [token, BACKEND_URL, refreshTrigger]);

  const handleUpdateRole = async (userId, newRole) => {
    setMessage('');
    setIsMessageError(false);
    try {
      // Note: Backend's update_user_role uses Form, so sending as FormData
      const formData = new FormData();
      formData.append('new_role', newRole);

      const response = await fetch(`${BACKEND_URL}/api/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          // 'Content-Type': 'application/json', // Do NOT set Content-Type for FormData
        },
        body: formData, // Send as FormData
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setIsMessageError(false);
        setRefreshTrigger(prev => prev + 1); // Trigger refresh
      } else {
        setMessage(data.detail || 'Failed to update user role.');
        setIsMessageError(true);
      }
    } catch (err) {
      console.error('Error updating user role:', err);
      setMessage('Network error updating user role.');
      setIsMessageError(true);
    }
  };

  return (
    <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-inner">
      <h3 className="text-2xl font-semibold mb-4 text-gray-800 dark:text-gray-200">User Management</h3>
      {message && (
        <div className={`px-4 py-3 rounded-lg relative mb-4 ${isMessageError ? 'bg-red-100 border border-red-400 text-red-700' : 'bg-green-100 border border-green-400 text-green-700'}`} role="alert">
          <strong className="font-bold">{isMessageError ? 'Error!' : 'Success!'}</strong>
          <span className="block sm:inline ml-2">{message}</span>
        </div>
      )}
      {loading ? (
        <div className="flex items-center justify-center p-4">
          <Loader2 className="animate-spin h-8 w-8 text-blue-500" />
          <p className="ml-3">Loading users...</p>
        </div>
      ) : error ? (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative">
          <strong className="font-bold">Error:</strong>
          <span className="block sm:inline ml-2">{error}</span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-600">
            <thead className="bg-gray-100 dark:bg-gray-600">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Username</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Email</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Role</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Wallet</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Activated</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {users.map((user) => (
                <tr key={user.user_id}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">{user.username}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{user.email}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{user.role}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">KSH {user.wallet_balance.toFixed(2)}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    {user.is_activated ? <CheckCircle className="h-5 w-5 text-green-500" /> : <XCircle className="h-5 w-5 text-red-500" />}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    {user.role === 'user' ? (
                      <button
                        onClick={() => handleUpdateRole(user.user_id, 'admin')}
                        className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-200 mr-2"
                      >
                        Make Admin
                      </button>
                    ) : (
                      <button
                        onClick={() => handleUpdateRole(user.user_id, 'user')}
                        className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-200 mr-2"
                      >
                        Make User
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// --- TransactionViewer Component (Admin) ---
const TransactionViewer = () => {
  const { token, BACKEND_URL } = useContext(AuthContext);
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchTransactions = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(`${BACKEND_URL}/api/admin/transactions`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (response.ok) {
          const data = await response.json();
          setTransactions(data.transactions);
        } else {
          const errorData = await response.json();
          setError(errorData.detail || 'Failed to fetch transactions.');
        }
      } catch (err) {
        console.error('Error fetching transactions:', err);
        setError('Network error or unable to connect to backend.');
      } finally {
        setLoading(false);
      }
    };
    fetchTransactions();
  }, [token, BACKEND_URL]);

  return (
    <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-inner">
      <h3 className="text-2xl font-semibold mb-4 text-gray-800 dark:text-gray-200">All Transactions</h3>
      {loading ? (
        <div className="flex items-center justify-center p-4">
          <Loader2 className="animate-spin h-8 w-8 text-blue-500" />
          <p className="ml-3">Loading transactions...</p>
        </div>
      ) : error ? (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative">
          <strong className="font-bold">Error:</strong>
          <span className="block sm:inline ml-2">{error}</span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-600">
            <thead className="bg-gray-100 dark:bg-gray-600">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">User ID</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Amount</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Method</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Date</th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {transactions.map((tx) => (
                <tr key={tx.transaction_id}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">{tx.user_id}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{tx.type}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">KSH {tx.amount.toFixed(2)}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                      tx.status === 'completed' ? 'bg-green-100 text-green-800' :
                      tx.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-red-100 text-red-800'
                    }`}>
                      {tx.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{tx.method || 'N/A'}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{new Date(tx.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// --- BroadcastNotificationSender Component (Admin) ---
const BroadcastNotificationSender = () => {
  const { token, BACKEND_URL } = useContext(AuthContext);
  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [notificationType, setNotificationType] = useState('INFO');
  const [loading, setLoading] = useState(false);
  const [responseMessage, setResponseMessage] = useState('');
  const [isError, setIsError] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResponseMessage('');
    setIsError(false);

    try {
      const apiResponse = await fetch(`${BACKEND_URL}/api/admin/notifications/broadcast`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ title, message, type: notificationType }),
      });

      const data = await apiResponse.json();
      if (apiResponse.ok) {
        setResponseMessage(data.message);
        setIsError(false);
        setTitle('');
        setMessage('');
      } else {
        setResponseMessage(data.detail || 'Failed to send broadcast notification.');
        setIsError(true);
      }
    } catch (err) {
      console.error('Error sending broadcast:', err);
      setResponseMessage('Network error or unable to connect to backend.');
      setIsError(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-inner max-w-lg mx-auto">
      <h3 className="text-2xl font-semibold mb-4 text-gray-800 dark:text-gray-200">Send Broadcast Notification</h3>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Title</label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full px-4 py-2 border rounded-md bg-gray-100 dark:bg-gray-600 dark:text-gray-100"
            required
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Message</label>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            rows="4"
            className="w-full px-4 py-2 border rounded-md bg-gray-100 dark:bg-gray-600 dark:text-gray-100"
            required
          ></textarea>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type</label>
          <select
            value={notificationType}
            onChange={(e) => setNotificationType(e.target.value)}
            className="w-full px-4 py-2 border rounded-md bg-gray-100 dark:bg-gray-600 dark:text-gray-100"
          >
            <option value="INFO">Info</option>
            <option value="SUCCESS">Success</option>
            <option value="WARNING">Warning</option>
            <option value="ERROR">Error</option>
          </select>
        </div>
        {responseMessage && (
          <div className={`text-sm ${isError ? 'text-red-600' : 'text-green-600'} text-center`}>
            {responseMessage}
          </div>
        )}
        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition duration-200 flex items-center justify-center"
          disabled={loading}
        >
          {loading && <Loader2 className="animate-spin h-5 w-5 mr-2" />}
          Send Broadcast
        </button>
      </form>
    </div>
  );
};

// --- TaskSubmissionReview Component (Admin) ---
const TaskSubmissionReview = () => {
  const { token, BACKEND_URL } = useContext(AuthContext);
  const [submissions, setSubmissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState('');
  const [isMessageError, setIsMessageError] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    const fetchSubmissions = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(`${BACKEND_URL}/api/admin/task-submissions/pending`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (response.ok) {
          const data = await response.json();
          setSubmissions(data.submissions);
        } else {
          const errorData = await response.json();
          setError(errorData.detail || 'Failed to fetch pending submissions.');
        }
      } catch (err) {
        console.error('Error fetching pending submissions:', err);
        setError('Network error or unable to connect to backend.');
      } finally {
        setLoading(false);
      }
    };
    fetchSubmissions();
  }, [token, BACKEND_URL, refreshTrigger]);

  const handleReviewAction = async (submissionId, action) => { // 'approve' or 'reject'
    setMessage('');
    setIsMessageError(false);
    try {
      const response = await fetch(`${BACKEND_URL}/api/admin/task-submissions/${submissionId}/${action}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setIsMessageError(false);
        setRefreshTrigger(prev => prev + 1); // Trigger refresh
      } else {
        setMessage(data.detail || `Failed to ${action} submission.`);
        setIsMessageError(true);
      }
    } catch (err) {
      console.error(`Error ${action}ing submission:`, err);
      setMessage(`Network error ${action}ing submission.`);
      setIsMessageError(true);
    }
  };

  return (
    <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-inner">
      <h3 className="text-2xl font-semibold mb-4 text-gray-800 dark:text-gray-200">Pending Task Submissions</h3>
      {message && (
        <div className={`px-4 py-3 rounded-lg relative mb-4 ${isMessageError ? 'bg-red-100 border border-red-400 text-red-700' : 'bg-green-100 border border-green-400 text-green-700'}`} role="alert">
          <strong className="font-bold">{isMessageError ? 'Error!' : 'Success!'}</strong>
          <span className="block sm:inline ml-2">{message}</span>
        </div>
      )}
      {loading ? (
        <div className="flex items-center justify-center p-4">
          <Loader2 className="animate-spin h-8 w-8 text-blue-500" />
          <p className="ml-3">Loading submissions...</p>
        </div>
      ) : error ? (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg relative">
          <strong className="font-bold">Error:</strong>
          <span className="block sm:inline ml-2">{error}</span>
        </div>
      ) : submissions.length === 0 ? (
        <p className="text-lg text-gray-600 dark:text-gray-400">No pending task submissions to review.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-600">
            <thead className="bg-gray-100 dark:bg-gray-600">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">User ID</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Task Title</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Reward</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Submitted At</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Completion Data</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {submissions.map((submission) => (
                <tr key={submission.submission_id}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">{submission.user_id}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{submission.task_title}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">KSH {submission.task_reward.toFixed(2)}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{new Date(submission.submitted_at).toLocaleString()}</td>
                  <td className="px-6 py-4 text-sm text-gray-700 dark:text-gray-300">
                    <pre className="whitespace-pre-wrap text-xs bg-gray-100 dark:bg-gray-600 p-2 rounded-md">{JSON.stringify(submission.completion_data, null, 2)}</pre>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleReviewAction(submission.submission_id, 'approve')}
                      className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-200 mr-2"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => handleReviewAction(submission.submission_id, 'reject')}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-200"
                    >
                      Reject
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


// --- App Wrapper with AuthProvider ---
// This is the default export for React apps.
export default function AppWrapper() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}
