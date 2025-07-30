import React, { useState, useEffect, createContext, useContext } from 'react';
import './App.css';

// Context for global state management
const AppContext = createContext();
const useAppContext = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useAppContext must be used within AppProvider');
  }
  return context;
};

// Notification Component
const Notification = ({ notification, onClose }) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      onClose();
    }, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  return (
    <div className={`notification ${notification.type}`}>
      <div className="notification-content">
        <h4>{notification.title}</h4>
        <p>{notification.message}</p>
      </div>
      <button className="notification-close" onClick={onClose}>×</button>
    </div>
  );
};

// Auth Components
const AuthPage = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    username: '', // <--- ADDED: Username field
    password: '',
    full_name: '',
    phone: '',
    referral_code: ''
  });
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();
  const [referralCodeLocked, setReferralCodeLocked] = useState(false);

  // Auto-fill referral_code from URL and lock field
  useEffect(() => {
    if (!isLogin) {
      const urlParams = new URLSearchParams(window.location.search);
      const referralFromUrl = urlParams.get('ref');
      if (referralFromUrl) {
        setFormData((prev) => ({
          ...prev,
          referral_code: referralFromUrl
        }));
        setReferralCodeLocked(true);
      } else {
        setReferralCodeLocked(false);
        setFormData((prev) => ({
          ...prev,
          referral_code: ''
        }));
      }
    }
    // eslint-disable-next-line
  }, [isLogin]);

  // Input validation patterns
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phonePattern = /^254\d{9}$/;
  const passwordPattern = /^.{6,}$/;
  const usernamePattern = /^[a-zA-Z0-9_]{3,20}$/; // Basic username validation

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Frontend validation for both login and registration
    if (!formData.password.trim()) { // Ensure password is not empty
      showNotification({
        title: 'Validation Error',
        message: 'Password is required.',
        type: 'error'
      });
      return;
    }
    if (!passwordPattern.test(formData.password)) {
      showNotification({
        title: 'Validation Error',
        message: 'Password must be at least 6 characters.',
        type: 'error'
      });
      return;
    }

    if (isLogin) {
      // Login specific validation (username required)
      if (!formData.username.trim()) {
        showNotification({
          title: 'Validation Error',
          message: 'Username is required for login.',
          type: 'error'
        });
        return;
      }
    } else {
      // Registration specific validation
      if (!formData.full_name.trim()) {
        showNotification({
          title: 'Validation Error',
          message: 'Full Name is required.',
          type: 'error'
        });
        return;
      }
      if (!formData.username.trim()) { // Username is also required for registration
        showNotification({
          title: 'Validation Error',
          message: 'Username is required for registration.',
          type: 'error'
        });
        return;
      }
      if (!usernamePattern.test(formData.username)) {
        showNotification({
          title: 'Validation Error',
          message: 'Username must be 3-20 characters, alphanumeric or underscores.',
          type: 'error'
        });
        return;
      }
      if (!phonePattern.test(formData.phone)) {
        showNotification({
          title: 'Validation Error',
          message: 'Phone number must be in format 254XXXXXXXXX.',
          type: 'error'
        });
        return;
      }
      if (!emailPattern.test(formData.email)) {
        showNotification({
          title: 'Validation Error',
          message: 'Please enter a valid email address.',
          type: 'error'
        });
        return;
      }
    }

    setLoading(true);

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const payload = isLogin
        ? { username: formData.username, password: formData.password } // Only send username and password for login
        : formData; // Send all fields for registration

      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload), // Use the specific payload
      });

      const data = await response.json();

      if (data.success) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        showNotification({
          title: 'Success!',
          message: data.message,
          type: 'success'
        });
        onLogin(data.user);
      } else {
        // IMPROVED ERROR HANDLING: Display detailed backend error if available
        const errorMessage = data.detail && Array.isArray(data.detail)
          ? data.detail.map(err => err.msg).join(', ')
          : data.detail || 'Authentication failed';

        showNotification({
          title: 'Error',
          message: errorMessage,
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card animated-card">
        <div className="auth-header">
          <h1>EarnPlatform</h1>
          <p>Start earning money with simple tasks</p>
        </div>

        <div className="auth-tabs">
          <button
            className={`tab ${isLogin ? 'active' : ''}`}
            onClick={() => setIsLogin(true)}
          >
            Login
          </button>
          <button
            className={`tab ${!isLogin ? 'active' : ''}`}
            onClick={() => setIsLogin(false)}
          >
            Register
          </button>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {/* Always show username field */}
          <div className="form-group">
            <input
              type="text" // Changed to type="text" for username
              placeholder="Username"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              required
              className="form-input"
              autoComplete="username"
              pattern="^[a-zA-Z0-9_]{3,20}$" // Apply username pattern
              title="Username must be 3-20 characters, alphanumeric or underscores."
            />
          </div>

          {/* Show email and other fields only for registration */}
          {!isLogin && (
            <>
              <div className="form-group">
                <input
                  type="text"
                  placeholder="Full Name"
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  required
                  className="form-input"
                  autoComplete="name"
                />
              </div>
              <div className="form-group">
                <input
                  type="email" // Email field is only for registration
                  placeholder="Email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                  className="form-input"
                  autoComplete="email"
                  pattern="^[^\s@]+@[^\s@]+\.[^\s@]+$"
                />
              </div>
              <div className="form-group">
                <input
                  type="tel"
                  placeholder="Phone Number (254XXXXXXXXX)"
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                  required
                  className="form-input"
                  pattern="254\d{9}"
                  autoComplete="tel"
                />
              </div>
              <div className="form-group">
                <input
                  type="text"
                  placeholder="Referral Code (Optional)"
                  value={formData.referral_code}
                  onChange={(e) => setFormData({ ...formData, referral_code: e.target.value })}
                  readOnly={referralCodeLocked}
                  disabled={referralCodeLocked}
                  className={`form-input ${referralCodeLocked ? 'locked' : ''}`}
                  style={referralCodeLocked ? { background: '#f0f0f0', cursor: 'not-allowed' } : {}}
                />
              </div>
            </>
          )}

          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required
              className="form-input"
              autoComplete={isLogin ? "current-password" : "new-password"}
              minLength={6}
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Processing...' : (isLogin ? 'Login' : 'Register')}
          </button>
        </form>

        {!isLogin && (
          <div className="auth-info">
            <p className="activation-notice">
              💡 New users need to deposit KSH 500 to activate their account and start earning!
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

// Dashboard Components (unchanged, copy from your previous code)
const WalletCard = ({ user, onDeposit, onWithdraw }) => {
  return (
    <div className="wallet-card animated-card">
      <div className="wallet-header">
        <h3>💰 My Wallet</h3>
        <div className={`activation-status ${user.is_activated ? 'active' : 'inactive'}`}>
          {user.is_activated ? '✅ Activated' : '⏳ Pending Activation'}
        </div>
      </div>
      <div className="wallet-balance">
        <span className="currency">KSH</span>
        <span className="amount">{user.wallet_balance.toFixed(2)}</span>
      </div>
      {!user.is_activated && (
        <div className="activation-notice">
          <p>Deposit KSH {user.activation_amount} to activate your account and start earning!</p>
        </div>
      )}
      <div className="wallet-actions">
        <button className="btn-deposit" onClick={onDeposit}>
          💳 Deposit
        </button>
        <button
          className="btn-withdraw"
          onClick={onWithdraw}
          disabled={!user.is_activated || user.wallet_balance < 100}
        >
          💸 Withdraw
        </button>
      </div>
      <div className="wallet-stats">
        <div className="stat">
          <span className="stat-label">Total Earned</span>
          <span className="stat-value">KSH {user.total_earned.toFixed(2)}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Total Withdrawn</span>
          <span className="stat-value">KSH {user.total_withdrawn.toFixed(2)}</span>
        </div>
      </div>
    </div>
  );
};

const TaskCard = ({ task, onComplete, completed = false }) => {
  const getTaskIcon = (type) => {
    switch (type) {
      case 'survey': return '📋';
      case 'ad': return '📺';
      case 'writing': return '✍️';
      case 'social': return '📱';
      default: return '⭐';
    }
  };

  return (
    <div className={`task-card animated-card ${completed ? 'completed' : ''}`}>
      <div className="task-header">
        <span className="task-icon">{getTaskIcon(task.type)}</span>
        <span className="task-reward">+KSH {task.reward}</span>
      </div>
      <h4 className="task-title">{task.title}</h4>
      <p className="task-description">{task.description}</p>
      <div className="task-footer">
        <span className="task-type">{task.type.toUpperCase()}</span>
        {!completed && (
          <button className="btn-task" onClick={() => onComplete(task)}>
            Complete
          </button>
        )}
      </div>
    </div>
  );
};

const ReferralCard = ({ user, stats }) => {
  const referralLink = `${window.location.origin}?ref=${user.referral_code}`;
  const { showNotification } = useAppContext();

  const copyReferralLink = () => {
    navigator.clipboard.writeText(referralLink);
    showNotification({
      title: 'Copied!',
      message: 'Referral link copied to clipboard',
      type: 'success'
    });
  };

  return (
    <div className="referral-card animated-card">
      <div className="referral-header">
        <h3>👥 Referral Program</h3>
        <div className="referral-reward">KSH 50 per referral</div>
      </div>
      <div className="referral-stats">
        <div className="stat">
          <span className="stat-value">{user.referral_count}</span>
          <span className="stat-label">Total Referrals</span>
        </div>
        <div className="stat">
          <span className="stat-value">KSH {user.referral_earnings.toFixed(2)}</span>
          <span className="stat-label">Referral Earnings</span>
        </div>
      </div>
      <div className="referral-link-section">
        <label>Your Referral Code:</label>
        <div className="referral-code-container">
          <input type="text" value={user.referral_code} readOnly className="referral-code" />
          <button className="btn-copy" onClick={copyReferralLink}>Copy Link</button>
        </div>
      </div>
      <div className="referral-encouragement">
        <p>🚀 Share your referral link and earn KSH 50 for each friend who joins and activates their account!</p>
        <p>💡 The more you refer, the more you earn!</p>
      </div>
    </div>
  );
};

const StatsCard = ({ title, value, icon, color }) => {
  return (
    <div className={`stats-card animated-card ${color}`}>
      <div className="stats-icon">{icon}</div>
      <div className="stats-content">
        <h4>{title}</h4>
        <div className="stats-value">{value}</div>
      </div>
    </div>
  );
};

// Modal Components (unchanged, copy from your previous code)
const DepositModal = ({ isOpen, onClose, onDeposit }) => {
  const [amount, setAmount] = useState('500');
  const [phone, setPhone] = useState('');
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();
  const phonePattern = /^254\d{9}$/;

  const handleDeposit = async (e) => {
    e.preventDefault();

    if (!phonePattern.test(phone)) {
      showNotification({
        title: 'Validation Error',
        message: 'Phone number must be in format 254XXXXXXXXX.',
        type: 'error'
      });
      return;
    }
    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/payments/deposit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          amount: parseFloat(amount),
          phone: phone
        }),
      });

      const data = await response.json();

      if (data.success) {
        showNotification({
          title: 'Deposit Initiated!',
          message: data.message,
          type: 'success'
        });
        onClose();
        onDeposit();
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Deposit failed',
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal animated-card">
        <div className="modal-header">
          <h3>💳 Deposit Money</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleDeposit}>
          <div className="form-group">
            <label>Amount (KSH)</label>
            <input
              type="number"
              min="1"
              step="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              required
              className="form-input"
            />
          </div>
          <div className="form-group">
            <label>M-Pesa Phone Number</label>
            <input
              type="tel"
              placeholder="254XXXXXXXXX"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              required
              className="form-input"
              pattern="254\d{9}"
            />
          </div>
          <div className="deposit-info">
            <p>📱 You will receive an M-Pesa prompt on your phone</p>
            <p>⏱️ Complete the payment within 5 minutes</p>
          </div>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Processing...' : 'Initiate Deposit'}
          </button>
        </form>
      </div>
    </div>
  );
};

const WithdrawModal = ({ isOpen, onClose, user, onWithdraw }) => {
  const [amount, setAmount] = useState('');
  const [phone, setPhone] = useState('');
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();
  const phonePattern = /^254\d{9}$/;

  const handleWithdraw = async (e) => {
    e.preventDefault();

    if (!phonePattern.test(phone)) {
      showNotification({
        title: 'Validation Error',
        message: 'Phone number must be in format 254XXXXXXXXX.',
        type: 'error'
      });
      return;
    }
    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/payments/withdraw`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          amount: parseFloat(amount),
          phone: phone
        }),
      });

      const data = await response.json();

      if (data.success) {
        showNotification({
          title: 'Withdrawal Requested!',
          message: data.message,
          type: 'success'
        });
        onWithdraw();
        onClose();
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Withdrawal failed',
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal animated-card">
        <div className="modal-header">
          <h3>💸 Withdraw Money</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleWithdraw}>
          <div className="form-group">
            <label>Amount (KSH)</label>
            <input
              type="number"
              min="100"
              max={user.wallet_balance}
              step="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              required
              className="form-input"
            />
            <small>Available: KSH {user.wallet_balance.toFixed(2)} | Minimum: KSH 100</small>
          </div>
          <div className="form-group">
            <label>M-Pesa Phone Number</label>
            <input
              type="tel"
              placeholder="254XXXXXXXXX"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              required
              className="form-input"
              pattern="254\d{9}"
            />
          </div>
          <div className="withdraw-info">
            <p>⏳ Processing time: 24-48 hours</p>
            <p>💰 Money will be sent to your M-Pesa account</p>
          </div>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Processing...' : 'Request Withdrawal'}
          </button>
        </form>
      </div>
    </div>
  );
};

// Main Dashboard Component (unchanged, copy from your previous code)
const Dashboard = ({ user, onLogout }) => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [dashboardData, setDashboardData] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showDepositModal, setShowDepositModal] = useState(false);
  const [showWithdrawModal, setShowWithdrawModal] = useState(false);
  const { theme, toggleTheme, showNotification } = useAppContext();

  useEffect(() => {
    fetchDashboardData();
    fetchTasks();
    // eslint-disable-next-line
  }, []);

  const fetchDashboardData = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/dashboard/stats`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await response.json();
      if (data.success) {
        setDashboardData(data);
      }
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchTasks = async () => {
    try {
      const token = localStorage.getItem('token');
      // Corrected endpoint from /api/tasks/available to /api/tasks as per backend
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/tasks`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await response.json();
      if (data.success) {
        setTasks(data.tasks);
      }
    } catch (error) {
      console.error('Error fetching tasks:', error);
    }
  };

  const completeTask = async (task) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/tasks/complete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          task_id: task.task_id,
          completion_data: { completed_at: new Date().toISOString() }
        }),
      });
      const data = await response.json();
      if (data.success) {
        showNotification({
          title: 'Task Completed!',
          message: data.message,
          type: 'success'
        });
        fetchDashboardData();
        fetchTasks();
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Task completion failed',
          type: 'error'
        });
      }
    } catch (error) {
      showNotification({
        title: 'Error',
        message: 'Network error. Please try again.',
        type: 'error'
      });
    }
  };

  const handleDeposit = () => {
    fetchDashboardData();
    setShowDepositModal(false);
  };

  const handleWithdraw = () => {
    fetchDashboardData();
    setShowWithdrawModal(false);
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading your dashboard...</p>
      </div>
    );
  }

  return (
    <div className={`dashboard ${theme}`}>
      <header className="dashboard-header">
        <div className="header-content">
          <h1>EarnPlatform</h1>
          <div className="header-actions">
            <button className="theme-toggle" onClick={toggleTheme}>
              {theme === 'light' ? '🌙' : '☀️'}
            </button>
            <button className="btn-logout" onClick={onLogout}>
              Logout
            </button>
          </div>
        </div>
        <nav className="dashboard-nav">
          <button
            className={`nav-item ${currentPage === 'dashboard' ? 'active' : ''}`}
            onClick={() => setCurrentPage('dashboard')}
          >
            📊 Dashboard
          </button>
          <button
            className={`nav-item ${currentPage === 'tasks' ? 'active' : ''}`}
            onClick={() => setCurrentPage('tasks')}
          >
            ⭐ Tasks
          </button>
          <button
            className={`nav-item ${currentPage === 'referrals' ? 'active' : ''}`}
            onClick={() => setCurrentPage('referrals')}
          >
            👥 Referrals
          </button>
        </nav>
      </header>
      <main className="dashboard-main">
        {currentPage === 'dashboard' && dashboardData && (
          <div className="dashboard-content">
            <div className="welcome-section">
              <h2>Welcome back, {dashboardData.user.full_name}! 👋</h2>
              <p>Ready to earn more money today?</p>
            </div>
            <div className="stats-grid">
              <StatsCard
                title="Wallet Balance"
                value={`KSH ${dashboardData.user.wallet_balance.toFixed(2)}`}
                icon="💰"
                color="green"
              />
              <StatsCard
                title="Total Earned"
                value={`KSH ${dashboardData.user.total_earned.toFixed(2)}`}
                icon="📈"
                color="blue"
              />
              <StatsCard
                title="Referrals"
                value={dashboardData.user.referral_count}
                icon="👥"
                color="purple"
              />
              <StatsCard
                title="Tasks Completed"
                value={dashboardData.task_completions}
                icon="✅"
                color="orange"
              />
            </div>
            <div className="dashboard-grid">
              <WalletCard
                user={dashboardData.user}
                onDeposit={() => setShowDepositModal(true)}
                onWithdraw={() => setShowWithdrawModal(true)}
              />
              <ReferralCard
                user={dashboardData.user}
                stats={dashboardData.referral_stats}
              />
            </div>
            {!dashboardData.user.is_activated && (
              <div className="activation-banner animated-card">
                <h3>🚀 Activate Your Account</h3>
                <p>Deposit KSH 500 to unlock all features and start earning money through tasks!</p>
                <button className="btn-primary" onClick={() => setShowDepositModal(true)}>
                  Activate Now
                </button>
              </div>
            )}
          </div>
        )}
        {currentPage === 'tasks' && (
          <div className="tasks-content">
            <div className="tasks-header">
              <h2>Available Tasks</h2>
              <p>Complete tasks to earn money and increase your wallet balance!</p>
            </div>
            {!user.is_activated ? (
              <div className="activation-required animated-card">
                <h3>Account Activation Required</h3>
                <p>Please activate your account by depositing KSH 500 to access tasks.</p>
                <button className="btn-primary" onClick={() => setShowDepositModal(true)}>
                  Activate Account
                </button>
              </div>
            ) : (
              <div className="tasks-grid">
                {tasks.map(task => (
                  <TaskCard
                    key={task.task_id || task.template_id}
                    task={task}
                    onComplete={completeTask}
                  />
                ))}
                {tasks.length === 0 && (
                  <div className="no-tasks">
                    <h3>🎉 All Tasks Completed!</h3>
                    <p>Great job! Check back later for new tasks.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
        {currentPage === 'referrals' && dashboardData && (
          <div className="referrals-content">
            <ReferralCard
              user={dashboardData.user}
              stats={dashboardData.referral_stats}
            />
            <div className="referral-tips animated-card">
              <h3>💡 Referral Tips</h3>
              <ul>
                <li>Share your referral link on social media platforms</li>
                <li>Tell friends and family about the earning opportunities</li>
                <li>Earn KSH 50 for each successful referral who activates their account</li>
                <li>The more you refer, the more passive income you generate!</li>
              </ul>
            </div>
          </div>
        )}
      </main>
      <DepositModal
        isOpen={showDepositModal}
        onClose={() => setShowDepositModal(false)}
        onDeposit={handleDeposit}
      />
      <WithdrawModal
        isOpen={showWithdrawModal}
        onClose={() => setShowWithdrawModal(false)}
        user={dashboardData?.user || user}
        onWithdraw={handleWithdraw}
      />
    </div>
  );
};

// Main App Component
const App = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notifications, setNotifications] = useState([]);
  const [theme, setTheme] = useState('light');

  useEffect(() => {
    // Check for existing session
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (token && savedUser) {
      setUser(JSON.parse(savedUser));
    }
    const urlParams = new URLSearchParams(window.location.search);
    const refCode = urlParams.get('ref');
    if (refCode) {
      localStorage.setItem('referral_code', refCode);
    }
    setLoading(false);
  }, []);

  const showNotification = (notification) => {
    const id = Date.now();
    setNotifications(prev => [...prev, { ...notification, id }]);
  };

  const removeNotification = (id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    if (user) {
      const token = localStorage.getItem('token');
      // Corrected endpoint for theme update to /api/user/profile (PUT)
      // Sending as JSON body as per FastAPI PUT endpoint for profile updates
      fetch(`${process.env.REACT_APP_BACKEND_URL}/api/user/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json', // Ensure Content-Type is JSON
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ theme: newTheme }), // Send theme as JSON body
      })
      .then(response => {
        if (!response.ok) {
          console.error('Failed to update theme on backend:', response.statusText);
        } else {
          // Optionally update local user state with new theme
          response.json().then(updatedUser => {
            localStorage.setItem('user', JSON.stringify(updatedUser));
            setUser(updatedUser);
          });
        }
      })
      .catch(error => console.error('Network error updating theme:', error));
    }
  };

  const handleLogin = (userData) => {
    setUser(userData);
    setTheme(userData.theme || 'light');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    showNotification({
      title: 'Logged Out',
      message: 'You have been successfully logged out.',
      type: 'info'
    });
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading EarnPlatform...</p>
      </div>
    );
  }

  return (
    <AppContext.Provider value={{
      showNotification,
      theme,
      toggleTheme
    }}>
      <div className={`app ${theme}`}>
        {!user ? (
          <AuthPage onLogin={handleLogin} />
        ) : (
          <Dashboard user={user} onLogout={handleLogout} />
        )}
        <div className="notification-container">
          {notifications.map(notification => (
            <Notification
              key={notification.id}
              notification={notification}
              onClose={() => removeNotification(notification.id)}
            />
          ))}
        </div>
      </div>
    </AppContext.Provider>
  );
};

export default App;
