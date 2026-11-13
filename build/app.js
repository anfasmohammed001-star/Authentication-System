'use strict';

(function () {
  const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,30}$/;
  const EMAIL_REGEX = /^[^\s@<>'"`\\]+@[^\s@<>'"`\\]+\.[^\s@<>'"`\\]{2,}$/;

  /**
   * Perform JSON HTTP request using Fetch API with credentials included for HttpOnly cookies.
   * @param {string} url
   * @param {RequestInit} [options]
   */
  async function apiRequest(url, options = {}) {
    const config = {
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      ...options,
    };

    let response;
    try {
      response = await fetch(url, config);
    } catch {
      return { ok: false, status: 0, payload: null };
    }

    const contentType = response.headers.get('content-type') || '';
    const isJson = contentType.includes('application/json');

    let payload = null;
    if (isJson) {
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }
    }

    // Only consider the request successful if HTTP status is 2xx, the response is JSON, and payload has no explicit error
    const isSuccess = response.ok && isJson && Boolean(payload && payload.success !== false);

    return {
      ok: isSuccess,
      status: response.status,
      payload,
    };
  }

  /**
   * Render status banner cleanly using textContent (XSS safe).
   */
  function showBanner(bannerEl, type, message) {
    if (!bannerEl) return;
    bannerEl.className = `alert alert-${type}`;
    bannerEl.textContent = message;
    bannerEl.classList.remove('hidden');
  }

  function hideBanner(bannerEl) {
    if (!bannerEl) return;
    bannerEl.className = 'alert hidden';
    bannerEl.textContent = '';
  }

  function setFieldError(inputEl, errorEl, message) {
    if (inputEl) {
      if (message) {
        inputEl.classList.add('input-invalid');
      } else {
        inputEl.classList.remove('input-invalid');
      }
    }
    if (errorEl) {
      if (message) {
        errorEl.textContent = message;
        errorEl.classList.remove('hidden');
      } else {
        errorEl.textContent = '';
        errorEl.classList.add('hidden');
      }
    }
  }

  function attachPasswordToggles() {
    const buttons = document.querySelectorAll('[data-toggle-password]');
    buttons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-toggle-password');
        const input = document.getElementById(targetId);
        if (!input) return;
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.textContent = isPassword ? 'Hide' : 'Show';
        btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      });
    });
  }

  function formatDateTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  }

  function evaluatePasswordPolicy(password) {
    const byteLength = new TextEncoder().encode(password).length;
    return {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      digit: /[0-9]/.test(password),
      special: /[^A-Za-z0-9\s]/.test(password),
      maxBytes: password.length > 0 && byteLength <= 72,
    };
  }

  function updatePasswordChecklist(password) {
    const rules = evaluatePasswordPolicy(password);
    const listEl = document.getElementById('password-rules');
    if (!listEl) return rules;

    Object.entries(rules).forEach(([ruleKey, isMet]) => {
      const item = listEl.querySelector(`[data-rule="${ruleKey}"]`);
      if (item) {
        item.classList.toggle('met', isMet);
      }
    });
    return rules;
  }

  async function redirectIfAlreadyAuthenticated() {
    // If the browser is already at /dashboard or /dashboard.html, never self-redirect
    const currentPath = window.location.pathname.toLowerCase();
    if (currentPath === '/dashboard' || currentPath.endsWith('dashboard.html')) {
      return;
    }

    try {
      const { ok, payload } = await apiRequest('/api/auth/me', { method: 'GET' });
      if (ok && payload && payload.success === true && payload.data && payload.data.user) {
        window.location.replace('/dashboard');
      }
    } catch {
      // Ignore network errors while checking passive auth status
    }
  }

  function initLoginPage() {
    const form = document.getElementById('login-form');
    const banner = document.getElementById('form-banner');
    const identifierInput = document.getElementById('login-identifier');
    const passwordInput = document.getElementById('login-password');
    const identifierError = document.getElementById('login-identifier-error');
    const passwordError = document.getElementById('login-password-error');
    const submitBtn = document.getElementById('login-submit-btn');

    const params = new URLSearchParams(window.location.search);
    const reason = params.get('reason');
    if (reason === 'auth_required') {
      showBanner(banner, 'info', 'Please sign in to access the protected dashboard.');
    } else if (reason === 'session_expired') {
      showBanner(banner, 'error', 'Your session expired or is invalid. Please sign in again.');
    } else if (reason === 'logged_out') {
      showBanner(banner, 'success', 'You have been securely logged out.');
    } else if (params.get('registered') === '1') {
      showBanner(banner, 'success', 'Account created successfully! Sign in with your credentials.');
    }

    // Redirect authenticated users directly to the dashboard
    redirectIfAlreadyAuthenticated();

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      hideBanner(banner);
      setFieldError(identifierInput, identifierError, '');
      setFieldError(passwordInput, passwordError, '');

      const identifier = identifierInput.value.trim();
      const password = passwordInput.value;
      let hasClientError = false;

      if (!identifier) {
        setFieldError(identifierInput, identifierError, 'Please enter your email or username.');
        hasClientError = true;
      } else if (identifier.includes('@') && !EMAIL_REGEX.test(identifier)) {
        setFieldError(identifierInput, identifierError, 'Please enter a valid email address.');
        hasClientError = true;
      } else if (!identifier.includes('@') && !USERNAME_REGEX.test(identifier)) {
        setFieldError(
          identifierInput,
          identifierError,
          'Username must be 3–30 characters (letters, numbers, _ or -).'
        );
        hasClientError = true;
      }

      if (!password) {
        setFieldError(passwordInput, passwordError, 'Please enter your password.');
        hasClientError = true;
      }

      if (hasClientError) {
        showBanner(banner, 'error', 'Please fix the highlighted fields and try again.');
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Signing in...';

      try {
        const { ok, payload } = await apiRequest('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ identifier, password }),
        });

        if (!ok) {
          const message =
            (payload && payload.message) || 'Invalid credentials. Please check your details.';
          showBanner(banner, 'error', message);
          return;
        }

        // HttpOnly cookie is set by the server; redirect to protected dashboard
        window.location.assign('/dashboard');
      } catch {
        showBanner(banner, 'error', 'Unable to reach the server. Please try again.');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In';
      }
    });
  }

  function initRegisterPage() {
    const form = document.getElementById('register-form');
    const banner = document.getElementById('form-banner');
    const usernameInput = document.getElementById('register-username');
    const emailInput = document.getElementById('register-email');
    const passwordInput = document.getElementById('register-password');
    const confirmInput = document.getElementById('register-confirm-password');

    const usernameError = document.getElementById('register-username-error');
    const emailError = document.getElementById('register-email-error');
    const passwordError = document.getElementById('register-password-error');
    const confirmError = document.getElementById('register-confirm-password-error');
    const submitBtn = document.getElementById('register-submit-btn');

    redirectIfAlreadyAuthenticated();

    passwordInput.addEventListener('input', () => {
      updatePasswordChecklist(passwordInput.value);
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      hideBanner(banner);
      setFieldError(usernameInput, usernameError, '');
      setFieldError(emailInput, emailError, '');
      setFieldError(passwordInput, passwordError, '');
      setFieldError(confirmInput, confirmError, '');

      const username = usernameInput.value.trim();
      const email = emailInput.value.trim().toLowerCase();
      const password = passwordInput.value;
      const confirmPassword = confirmInput.value;
      let hasClientError = false;

      if (!username) {
        setFieldError(usernameInput, usernameError, 'Username is required.');
        hasClientError = true;
      } else if (!USERNAME_REGEX.test(username)) {
        setFieldError(
          usernameInput,
          usernameError,
          'Username must be 3–30 characters (letters, numbers, underscores, hyphens).'
        );
        hasClientError = true;
      }

      if (!email) {
        setFieldError(emailInput, emailError, 'Email address is required.');
        hasClientError = true;
      } else if (!EMAIL_REGEX.test(email)) {
        setFieldError(emailInput, emailError, 'Please enter a valid email address.');
        hasClientError = true;
      }

      const rules = updatePasswordChecklist(password);
      if (!password) {
        setFieldError(passwordInput, passwordError, 'Password is required.');
        hasClientError = true;
      } else if (!Object.values(rules).every(Boolean)) {
        setFieldError(
          passwordInput,
          passwordError,
          'Password does not satisfy all security requirements above.'
        );
        hasClientError = true;
      }

      if (!confirmPassword) {
        setFieldError(confirmInput, confirmError, 'Please confirm your password.');
        hasClientError = true;
      } else if (password !== confirmPassword) {
        setFieldError(confirmInput, confirmError, 'Passwords do not match.');
        hasClientError = true;
      }

      if (hasClientError) {
        showBanner(banner, 'error', 'Please resolve the validation errors before submitting.');
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating account...';

      try {
        const { ok, status, payload } = await apiRequest('/api/auth/register', {
          method: 'POST',
          body: JSON.stringify({ username, email, password }),
        });

        if (!ok) {
          const message =
            (payload && payload.message) || 'Registration failed. Please review your details.';
          if (payload && Array.isArray(payload.errors)) {
            payload.errors.forEach((err) => {
              if (err.field === 'username') setFieldError(usernameInput, usernameError, err.message);
              if (err.field === 'email') setFieldError(emailInput, emailError, err.message);
              if (err.field === 'password') setFieldError(passwordInput, passwordError, err.message);
            });
          } else if (status === 409) {
            showBanner(banner, 'error', message);
            return;
          }
          showBanner(banner, 'error', message);
          return;
        }

        showBanner(banner, 'success', 'Account created successfully! Redirecting to sign in...');
        window.setTimeout(() => {
          window.location.assign('/?registered=1');
        }, 750);
      } catch {
        showBanner(banner, 'error', 'Unable to connect to the server. Please try again.');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Account';
      }
    });
  }

  async function initDashboardPage() {
    const loadingEl = document.getElementById('dashboard-loading');
    const contentEl = document.getElementById('dashboard-content');
    const logoutBtn = document.getElementById('logout-btn');
    const usernameEl = document.getElementById('welcome-username');
    const emailEl = document.getElementById('welcome-email');

    // Enforce client-side route protection by verifying session with backend
    try {
      const { ok, status, payload } = await apiRequest('/api/dashboard', { method: 'GET' });
      if (!ok || !payload || !payload.data || !payload.data.user) {
        const currentPath = window.location.pathname.toLowerCase();
        // Avoid redirecting if already on login/root
        if (currentPath !== '/' && currentPath !== '/index.html' && currentPath !== '/login' && currentPath !== '/login.html') {
          const reason = status === 401 ? 'auth_required' : 'session_expired';
          window.location.replace(`/?reason=${reason}`);
        }
        return;
      }

      const { user } = payload.data;

      if (usernameEl) {
        usernameEl.textContent = user.username;
      }
      if (emailEl) {
        emailEl.textContent = user.email;
      }

      if (loadingEl) loadingEl.classList.add('hidden');
      if (contentEl) contentEl.classList.remove('hidden');
    } catch {
      const currentPath = window.location.pathname.toLowerCase();
      if (currentPath !== '/' && currentPath !== '/index.html' && currentPath !== '/login' && currentPath !== '/login.html') {
        window.location.replace('/?reason=auth_required');
      }
      return;
    }

    if (logoutBtn) {
      logoutBtn.addEventListener('click', async () => {
        logoutBtn.disabled = true;
        logoutBtn.textContent = 'Logging out...';

        try {
          await apiRequest('/api/auth/logout', { method: 'POST' });
        } catch {
          // Proceed with redirect even if request fails
        } finally {
          sessionStorage.clear();
          window.location.replace('/?reason=logged_out');
        }
      });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    attachPasswordToggles();
    const page = document.body.getAttribute('data-page');
    if (page === 'login') initLoginPage();
    if (page === 'register') initRegisterPage();
    if (page === 'dashboard') initDashboardPage();
  });
})();

