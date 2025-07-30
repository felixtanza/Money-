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
    username: '',
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
      // FIX: Ensure 'urlParams.get' is used here, not 'url.get'
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
      case 'referral': return '🤝'; // Added icon for referral task type
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

// New Task Completion Modal
const TaskCompletionModal = ({ isOpen, onClose, task, onSubmitCompletion }) => {
  const [answers, setAnswers] = useState({});
  const [loading, setLoading] = useState(false);
  const { showNotification } = useAppContext();

  useEffect(() => {
    if (isOpen && task && task.requirements) {
      // Initialize answers based on task requirements
      const initialAnswers = {};
      try {
        const parsedRequirements = typeof task.requirements === 'string'
          ? JSON.parse(task.requirements)
          : task.requirements;

        if (Array.isArray(parsedRequirements)) {
          parsedRequirements.forEach(req => {
            if (req.field_name) {
              initialAnswers[req.field_name] = ''; // Default empty string for text/number
              if (req.type === 'checkbox') {
                initialAnswers[req.field_name] = false; // Default false for checkbox
              }
            }
          });
        }
      } catch (e) {
        console.error("Failed to parse task requirements JSON:", e);
        showNotification({ title: 'Error', message: 'Invalid task requirements format.', type: 'error' });
      }
      setAnswers(initialAnswers);
    }
  }, [isOpen, task, showNotification]);

  const handleAnswerChange = (fieldName, value, type) => {
    setAnswers(prev => ({
      ...prev,
      [fieldName]: type === 'number' ? parseFloat(value) || 0 : (type === 'checkbox' ? value : value)
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    // Basic validation for required fields in the modal
    try {
      const parsedRequirements = typeof task.requirements === 'string'
        ? JSON.parse(task.requirements)
        : task.requirements;

      if (Array.isArray(parsedRequirements)) {
        for (const req of parsedRequirements) {
          if (req.required && (answers[req.field_name] === undefined || answers[req.field_name] === '' || (req.type === 'checkbox' && answers[req.field_name] === false))) {
            showNotification({
              title: 'Validation Error',
              message: `Please provide an answer for "${req.label}".`,
              type: 'error'
            });
            setLoading(false);
            return;
          }
        }
      }
    } catch (e) {
      console.error("Failed to parse task requirements JSON during submission validation:", e);
      showNotification({ title: 'Error', message: 'Internal error validating task. Please try again.', type: 'error' });
      setLoading(false);
      return;
    }

    await onSubmitCompletion(task, answers);
    setLoading(false);
    onClose();
  };

  if (!isOpen || !task) return null;

  let parsedRequirements = [];
  try {
    parsedRequirements = typeof task.requirements === 'string'
      ? JSON.parse(task.requirements)
      : task.requirements;
    if (!Array.isArray(parsedRequirements)) {
      parsedRequirements = []; // Ensure it's an array for iteration
    }
  } catch (e) {
    console.error("Error parsing task requirements:", e);
    parsedRequirements = [];
  }

  return (
    <div className="modal-overlay">
      <div className="modal animated-card">
        <div className="modal-header">
          <h3>Complete Task: {task.title}</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <p className="task-modal-description">{task.description}</p>
          {parsedRequirements.length > 0 ? (
            <div className="task-requirements-form">
              <h4>Questions:</h4>
              {parsedRequirements.map((req, index) => (
                <div className="form-group" key={index}>
                  <label>{req.label} {req.required && <span className="required-star">*</span>}</label>
                  {req.type === 'text' && (
                    <input
                      type="text"
                      className="form-input"
                      value={answers[req.field_name] || ''}
                      onChange={(e) => handleAnswerChange(req.field_name, e.target.value, req.type)}
                      required={req.required}
                    />
                  )}
                  {req.type === 'number' && (
                    <input
                      type="number"
                      className="form-input"
                      value={answers[req.field_name] || ''}
                      onChange={(e) => handleAnswerChange(req.field_name, e.target.value, req.type)}
                      required={req.required}
                      min={req.min}
                      max={req.max}
                      step={req.step || 'any'}
                    />
                  )}
                  {req.type === 'checkbox' && (
                    <div className="checkbox-group">
                      <input
                        type="checkbox"
                        id={`checkbox-${req.field_name}-${index}`}
                        checked={!!answers[req.field_name]}
                        onChange={(e) => handleAnswerChange(req.field_name, e.target.checked, req.type)}
                        required={req.required}
                      />
                      <label htmlFor={`checkbox-${req.field_name}-${index}`}>{req.checkbox_label || 'Check to confirm'}</label>
                    </div>
                  )}
                  {/* Add more input types as needed (e.g., textarea, select) */}
                </div>
              ))}
            </div>
          ) : (
            <p>No specific questions for this task. Click "Confirm Completion" to proceed.</p>
          )}
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Submitting...' : 'Confirm Completion'}
          </button>
        </form>
      </div>
    </div>
  );
};


// Admin Components
const AdminDashboard = ({ user, onLogout }) => {
  const [adminPage, setAdminPage] = useState('users');
  const [users, setUsers] = useState([]);
  const [transactions, setTransactions] = useState([]);
  const [tasks, setTasks] = useState([]); // For managing all tasks
  const [submissions, setSubmissions] = useState([]); // New state for pending submissions
  const [loading, setLoading] = useState(true);
  const { showNotification } = useAppContext();

  // State for new task form
  const [newTask, setNewTask] = useState({
    title: '',
    description: '',
    reward: 0,
    type: 'survey',
    requirements: '[]', // Changed to string for JSON input
    auto_approve: true
  });
  // State for broadcast notification
  const [broadcastNotification, setBroadcastNotification] = useState({
    title: '',
    message: ''
  });

  useEffect(() => {
    fetchAdminData();
    // eslint-disable-next-line
  }, [adminPage]); // Refetch data when admin page changes

  const fetchAdminData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const headers = { 'Authorization': `Bearer ${token}` };

      let data;
      if (adminPage === 'users') {
        const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/users`, { headers });
        data = await response.json();
        if (response.ok && Array.isArray(data)) { // Ensure data is an array
          setUsers(data);
        } else {
          showNotification({ title: 'Error', message: data.detail || 'Failed to fetch users', type: 'error' });
          setUsers([]);
        }
      } else if (adminPage === 'transactions') {
        const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/transactions`, { headers });
        data = await response.json();
        if (response.ok && data.success && Array.isArray(data.transactions)) {
          setTransactions(data.transactions);
        } else {
          showNotification({ title: 'Error', message: data.detail || 'Failed to fetch transactions', type: 'error' });
          setTransactions([]);
        }
      } else if (adminPage === 'tasks') {
        const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/tasks`, { headers }); // Reusing /api/tasks for admin to view all
        data = await response.json();
        if (response.ok && data.success && Array.isArray(data.tasks)) {
          setTasks(data.tasks);
        } else {
          showNotification({ title: 'Error', message: data.detail || 'Failed to fetch tasks', type: 'error' });
          setTasks([]);
        }
      } else if (adminPage === 'submissions') { // New case for submissions
        // This endpoint needs to be implemented in your backend
        const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/task-submissions/pending`, { headers });
        data = await response.json();
        if (response.ok && data.success && Array.isArray(data.submissions)) {
          setSubmissions(data.submissions);
        } else {
          showNotification({ title: 'Error', message: data.detail || 'Failed to fetch pending submissions. Ensure backend endpoint is implemented.', type: 'error' });
          setSubmissions([]);
        }
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error fetching admin data.', type: 'error' });
      console.error('Error fetching admin data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateUserRole = async (userId, newRole) => {
    // IMPORTANT: Replace window.confirm with a custom modal for production
    if (!window.confirm(`Are you sure you want to change role for user ${userId} to ${newRole}?`)) {
      return;
    }
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ new_role: newRole }), // Send as JSON body
      });
      const data = await response.json();
      if (response.ok) {
        showNotification({ title: 'Success', message: `User ${userId} role updated to ${newRole}`, type: 'success' });
        fetchAdminData(); // Refresh user list
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to update user role', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error updating user role.', type: 'error' });
      console.error('Error updating user role:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTask = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      // Parse requirements string to JSON object
      const taskPayload = {
        ...newTask,
        requirements: newTask.requirements ? JSON.parse(newTask.requirements) : {}
      };

      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/tasks`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(taskPayload), // Send parsed requirements
      });
      const data = await response.json();
      if (response.ok) {
        showNotification({ title: 'Success', message: 'Task created successfully!', type: 'success' });
        setNewTask({ title: '', description: '', reward: 0, type: 'survey', requirements: '[]', auto_approve: true }); // Reset form
        fetchAdminData(); // Refresh tasks list
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to create task', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error creating task or invalid JSON in requirements.', type: 'error' });
      console.error('Error creating task:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleBroadcastNotification = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/notifications/broadcast`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(broadcastNotification),
      });
      const data = await response.json();
      if (response.ok) {
        showNotification({ title: 'Success', message: 'Notification broadcasted!', type: 'success' });
        setBroadcastNotification({ title: '', message: '' }); // Reset form
      } else {
        showNotification({ title: 'Error', message: data.detail || 'Failed to broadcast notification', type: 'error' });
      }
    } catch (error) {
      showNotification({ title: 'Error', message: 'Network error broadcasting notification.', type: 'error' });
      console.error('Error broadcasting notification:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleApproveSubmission = async (submissionId) => {
    showNotification({ title: 'Info', message: 'Approve functionality is pending backend implementation.', type: 'info' });
    // TODO: Implement backend endpoint for PUT /api/admin/task-submissions/{submission_id}/approve
    // try {
    //   const token = localStorage.getItem('token');
    //   const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/task-submissions/${submissionId}/approve`, {
    //     method: 'PUT',
    //     headers: { 'Authorization': `Bearer ${token}` }
    //   });
    //   const data = await response.json();
    //   if (response.ok) {
    //     showNotification({ title: 'Success', message: 'Submission approved!', type: 'success' });
    //     fetchAdminData();
    //   } else {
    //     showNotification({ title: 'Error', message: data.detail || 'Failed to approve submission', type: 'error' });
    //   }
    // } catch (error) {
    //   showNotification({ title: 'Error', message: 'Network error approving submission.', type: 'error' });
    // }
  };

  const handleRejectSubmission = async (submissionId) => {
    showNotification({ title: 'Info', message: 'Reject functionality is pending backend implementation.', type: 'info' });
    // TODO: Implement backend endpoint for PUT /api/admin/task-submissions/{submission_id}/reject
    // try {
    //   const token = localStorage.getItem('token');
    //   const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/admin/task-submissions/${submissionId}/reject`, {
    //     method: 'PUT',
    //     headers: { 'Authorization': `Bearer ${token}` }
    //   });
    //   const data = await response.json();
    //   if (response.ok) {
    //     showNotification({ title: 'Success', message: 'Submission rejected!', type: 'success' });
    //     fetchAdminData();
    //   } else {
    //     showNotification({ title: 'Error', message: data.detail || 'Failed to reject submission', type: 'error' });
    //   }
    // } catch (error) {
    //   showNotification({ title: 'Error', message: 'Network error rejecting submission.', type: 'error' });
    // }
  };

  return (
    <div className="dashboard admin-dashboard">
      <header className="dashboard-header">
        <div className="header-content">
          <h1>Admin Panel</h1>
          <div className="header-actions">
            <button className="btn-logout" onClick={onLogout}>
              Logout
            </button>
          </div>
        </div>
        <nav className="dashboard-nav">
          <button
            className={`nav-item ${adminPage === 'users' ? 'active' : ''}`}
            onClick={() => setAdminPage('users')}
          >
            👥 Users
          </button>
          <button
            className={`nav-item ${adminPage === 'tasks' ? 'active' : ''}`}
            onClick={() => setAdminPage('tasks')}
          >
            ⭐ Tasks
          </button>
          <button
            className={`nav-item ${adminPage === 'transactions' ? 'active' : ''}`}
            onClick={() => setAdminPage('transactions')}
          >
            💸 Transactions
          </button>
          <button
            className={`nav-item ${adminPage === 'submissions' ? 'active' : ''}`} // New Submissions tab 
            onClick={() => setAdminPage('submissions')}
          >
            📝 Submissions
          </button>
          <button
            className={`nav-item ${adminPage === 'notifications' ? 'active' : ''}`}
            onClick={() => setAdminPage('notifications')}
          >
            🔔 Notifications
          </button>
        </nav>
      </header>

      <main className="dashboard-main">
        {loading ? (
          <div className="loading-container">
            <div className="loading-spinner"></div>
            <p>Loading admin data...</p>
          </div>
        ) : (
          <>
            {adminPage === 'users' && (
              <div className="admin-section animated-card">
                <h2>User Management</h2>
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>User ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Role</th>
                        <th>Activated</th>
                        <th>Balance</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map(u => (
                        <tr key={u.user_id}>
                          <td>{u.user_id.substring(0, 8)}...</td>
                          <td>{u.username}</td>
                          <td>{u.email}</td>
                          <td>{u.phone}</td>
                          <td>{u.role}</td>
                          <td>{u.is_activated ? 'Yes' : 'No'}</td>
                          <td>{u.wallet_balance.toFixed(2)}</td>
                          <td>
                            <select
                              value={u.role}
                              onChange={(e) => handleUpdateUserRole(u.user_id, e.target.value)}
                              className="form-select"
                            >
                              <option value="user">User</option>
                              <option value="admin">Admin</option>
                            </select>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {users.length === 0 && <p className="no-data-message">No users found.</p>}
              </div>
            )}

            {adminPage === 'tasks' && (
              <div className="admin-section animated-card">
                <h2>Task Management</h2>
                <div className="form-section">
                  <h3>Create New Task</h3>
                  <form onSubmit={handleCreateTask} className="admin-form">
                    <div className="form-group">
                      <input
                        type="text"
                        placeholder="Task Title"
                        value={newTask.title}
                        onChange={(e) => setNewTask({ ...newTask, title: e.target.value })}
                        required
                        className="form-input"
                      />
                    </div>
                    <div className="form-group">
                      <textarea
                        placeholder="Task Description"
                        value={newTask.description}
                        onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
                        required
                        className="form-input"
                      ></textarea>
                    </div>
                    <div className="form-group">
                      <input
                        type="number"
                        placeholder="Reward Amount (KSH)"
                        value={newTask.reward}
                        onChange={(e) => setNewTask({ ...newTask, reward: parseFloat(e.target.value) || 0 })}
                        min="0"
                        step="0.01"
                        required
                        className="form-input"
                      />
                    </div>
                    <div className="form-group">
                      <select
                        value={newTask.type}
                        onChange={(e) => setNewTask({ ...newTask, type: e.target.value })}
                        className="form-select"
                      >
                        <option value="survey">Survey</option>
                        <option value="ad">Ad View</option>
                        <option value="writing">Writing</option>
                        <option value="social">Social Media</option>
                        <option value="referral">Referral</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label htmlFor="requirements-json">Requirements (JSON Array of Objects)</label>
                      <textarea
                        id="requirements-json"
                        placeholder='e.g., [{"type": "text", "label": "Your Answer", "field_name": "answer_text", "required": true}]'
                        value={newTask.requirements}
                        onChange={(e) => setNewTask({ ...newTask, requirements: e.target.value })}
                        className="form-input"
                        rows="5"
                      ></textarea>
                      <small>Define questions/inputs for the user to complete this task. Must be valid JSON.</small>
                    </div>
                    <div className="form-group checkbox-group">
                      <input
                        type="checkbox"
                        id="autoApprove"
                        checked={newTask.auto_approve}
                        onChange={(e) => setNewTask({ ...newTask, auto_approve: e.target.checked })}
                      />
                      <label htmlFor="autoApprove">Auto Approve (Reward Instantly)</label>
                    </div>
                    <button type="submit" className="btn-primary" disabled={loading}>
                      Create Task
                    </button>
                  </form>
                </div>

                <h3>All Existing Tasks</h3>
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Title</th>
                        <th>Type</th>
                        <th>Reward</th>
                        <th>Auto Approve</th>
                        <th>Requirements</th>
                        <th>Created At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tasks.map(t => (
                        <tr key={t.task_id}>
                          <td>{t.title}</td>
                          <td>{t.type}</td>
                          <td>{t.reward.toFixed(2)}</td>
                          <td>{t.auto_approve ? 'Yes' : 'No'}</td>
                          <td>{t.requirements ? JSON.stringify(t.requirements).substring(0, 50) + '...' : 'N/A'}</td>
                          <td>{new Date(t.created_at).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {tasks.length === 0 && <p className="no-data-message">No tasks found.</p>}
              </div>
            )}

            {adminPage === 'transactions' && (
              <div className="admin-section animated-card">
                <h2>Transaction History</h2>
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Txn ID</th>
                        <th>User ID</th>
                        <th>Type</th>
                        <th>Amount</th>
                        <th>Status</th>
                        <th>Method</th>
                        <th>Created At</th>
                        <th>Completed At</th>
                        <th>M-Pesa Receipt</th>
                      </tr>
                    </thead>
                    <tbody>
                      {transactions.map(t => (
                        <tr key={t.transaction_id}>
                          <td>{t.transaction_id.substring(0, 8)}...</td>
                          <td>{t.user_id.substring(0, 8)}...</td>
                          <td>{t.type}</td>
                          <td>{t.amount.toFixed(2)}</td>
                          <td>{t.status}</td>
                          <td>{t.method}</td>
                          <td>{new Date(t.created_at).toLocaleDateString()}</td>
                          <td>{t.completed_at ? new Date(t.completed_at).toLocaleDateString() : 'N/A'}</td>
                          <td>{t.mpesa_receipt || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {transactions.length === 0 && <p className="no-data-message">No transactions found.</p>}
              </div>
            )}

            {adminPage === 'submissions' && ( // New Submissions Section
              <div className="admin-section animated-card">
                <h2>Pending Task Submissions</h2>
                <p className="info-message">
                  This section will display tasks submitted by users that require manual approval.
                  (Backend endpoint for fetching submissions is pending implementation.)
                </p>
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Submission ID</th>
                        <th>User ID</th>
                        <th>Task Title</th>
                        <th>Submitted Answers</th>
                        <th>Submitted At</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {submissions.length > 0 ? (
                        submissions.map(s => (
                          <tr key={s.submission_id}>
                            <td>{s.submission_id.substring(0, 8)}...</td>
                            <td>{s.user_id.substring(0, 8)}...</td>
                            <td>{s.task_title}</td>
                            <td>{s.answers ? JSON.stringify(s.answers).substring(0, 50) + '...' : 'N/A'}</td>
                            <td>{new Date(s.submitted_at).toLocaleDateString()}</td>
                            <td>
                              <button className="btn-success" onClick={() => handleApproveSubmission(s.submission_id)}>Approve</button>
                              <button className="btn-danger" onClick={() => handleRejectSubmission(s.submission_id)}>Reject</button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="6" className="no-data-message">No pending submissions found.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {adminPage === 'notifications' && (
              <div className="admin-section animated-card">
                <h2>Broadcast Notifications</h2>
                <div className="form-section">
                  <h3>Send New Broadcast</h3>
                  <form onSubmit={handleBroadcastNotification} className="admin-form">
                    <div className="form-group">
                      <input
                        type="text"
                        placeholder="Notification Title"
                        value={broadcastNotification.title}
                        onChange={(e) => setBroadcastNotification({ ...broadcastNotification, title: e.target.value })}
                        required
                        className="form-input"
                      />
                    </div>
                    <div className="form-group">
                      <textarea
                        placeholder="Notification Message"
                        value={broadcastNotification.message}
                        onChange={(e) => setBroadcastNotification({ ...broadcastNotification, message: e.target.value })}
                        required
                        className="form-input"
                      ></textarea>
                    </div>
                    <button type="submit" className="btn-primary" disabled={loading}>
                      Broadcast Notification
                    </button>
                  </form>
                </div>
                <p className="info-message">Notifications sent from here will be visible to all users.</p>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
};


// Main Dashboard Component
const Dashboard = ({ user, onLogout }) => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [dashboardData, setDashboardData] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showDepositModal, setShowDepositModal] = useState(false);
  const [showWithdrawModal, setShowWithdrawModal] = useState(false);
  const [showTaskCompletionModal, setShowTaskCompletionModal] = useState(false); // New state for task completion modal
  const [selectedTaskForCompletion, setSelectedTaskForCompletion] = useState(null); // New state for selected task
  const { theme, toggleTheme, showNotification } = useAppContext(); // Destructure showNotification

  useEffect(() => {
    fetchDashboardData();
    fetchTasks();
    fetchUserNotifications(); // Fetch notifications on dashboard load
    const notificationInterval = setInterval(fetchUserNotifications, 60000); // Poll every 60 seconds
    return () => clearInterval(notificationInterval); // Cleanup interval on unmount
    // eslint-disable-next-line
  }, [user]); // Re-fetch when user object changes (e.g., after login)

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
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/tasks`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await response.json();
      if (data.success) {
        // Assuming backend /api/tasks returns only available/uncompleted tasks for the user
        setTasks(data.tasks);
      }
    } catch (error) {
      console.error('Error fetching tasks:', error);
      showNotification({ title: 'Error', message: 'Failed to fetch tasks.', type: 'error' });
    }
  };

  const fetchUserNotifications = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) return; // Don't fetch if not logged in

      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/notifications`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await response.json();
      if (response.ok && data.success && Array.isArray(data.notifications)) {
        // Filter for unread notifications and display them
        data.notifications.forEach(notif => {
          // You might want a more sophisticated way to track 'read' status
          // For now, we'll just show them if they are 'unread' (or always show new ones)
          if (!notif.read) { // Assuming a 'read' field in your notification schema
            showNotification({
              title: notif.title,
              message: notif.message,
              type: notif.type || 'info' // Use type from backend or default to 'info'
            });
            // Optionally, mark as read on the backend after displaying
            markNotificationAsRead(notif.notification_id);
          }
        });
      }
    } catch (error) {
      console.error('Error fetching user notifications:', error);
    }
  };

  const markNotificationAsRead = async (notificationId) => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/notifications/${notificationId}/read`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      // No need to show a notification for marking as read, just update backend
    } catch (error) {
      console.error('Error marking notification as read:', error);
    }
  };

  const initiateTaskCompletion = (task) => {
    setSelectedTaskForCompletion(task);
    setShowTaskCompletionModal(true);
  };

  const submitTaskCompletion = async (task, answers) => {
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
          completion_data: answers // Send the collected answers
        }),
      });
      const data = await response.json();
      if (data.success) {
        showNotification({
          title: 'Task Submitted!',
          message: data.message,
          type: 'success'
        });
        fetchDashboardData();
        fetchTasks(); // Re-fetch tasks to update the list
      } else {
        showNotification({
          title: 'Error',
          message: data.detail || 'Task submission failed',
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
          {user.role === 'admin' && ( // Admin tab for regular dashboard nav
            <button
              className={`nav-item ${currentPage === 'admin' ? 'active' : ''}`}
              onClick={() => setCurrentPage('admin')}
            >
              ⚙️ Admin
            </button>
          )}
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
                    onComplete={initiateTaskCompletion} // Changed to open modal
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
        {currentPage === 'admin' && user.role === 'admin' && (
          <AdminDashboard user={user} onLogout={onLogout} />
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
      <TaskCompletionModal // New Task Completion Modal
        isOpen={showTaskCompletionModal}
        onClose={() => setShowTaskCompletionModal(false)}
        task={selectedTaskForCompletion}
        onSubmitCompletion={submitTaskCompletion}
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
      const parsedUser = JSON.parse(savedUser);
      setUser(parsedUser);
      setTheme(parsedUser.theme || 'light'); // Set theme from user data
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
