const validator = require('validator');

const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,30}$/;
const CONTROL_CHARS_GLOBAL_REGEX = /[\x00-\x1F\x7F]/g;
const CONTROL_CHARS_TEST_REGEX = /[\x00-\x1F\x7F]/;
const DANGEROUS_HTML_CHARS_REGEX = /[<>'"`\\]/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Strip ASCII control characters and null bytes, then trim whitespace.
 * @param {string} value
 * @returns {string}
 */
function sanitizeText(value) {
  return value.replace(CONTROL_CHARS_GLOBAL_REGEX, '').trim();
}

/**
 * Escape HTML special characters for safe output rendering (XSS defense-in-depth).
 * @param {string} value
 * @returns {string}
 */
function escapeHtml(value) {
  if (typeof value !== 'string') return '';
  return validator.escape(value);
}

/**
 * Recursively strip MongoDB query operator keys (`$...`, keys containing `.`)
 * and prototype pollution keys (`__proto__`, `constructor`, `prototype`) in-place.
 * @param {unknown} target
 * @returns {unknown}
 */
function sanitizeObjectKeys(target) {
  if (!target || typeof target !== 'object') {
    return target;
  }

  if (Array.isArray(target)) {
    for (let i = 0; i < target.length; i += 1) {
      target[i] = sanitizeObjectKeys(target[i]);
    }
    return target;
  }

  const keys = Object.keys(target);
  for (const key of keys) {
    if (FORBIDDEN_KEYS.has(key) || key.startsWith('$') || key.includes('.')) {
      delete target[key];
      continue;
    }
    target[key] = sanitizeObjectKeys(target[key]);
  }
  return target;
}

/**
 * Express middleware to sanitize incoming request body, params, and query objects
 * against NoSQL operator injection and prototype pollution.
 */
function sanitizeRequestMiddleware(req, _res, next) {
  if (req.body && typeof req.body === 'object') {
    sanitizeObjectKeys(req.body);
  }
  if (req.params && typeof req.params === 'object') {
    sanitizeObjectKeys(req.params);
  }
  if (req.query && typeof req.query === 'object') {
    sanitizeObjectKeys(req.query);
  }
  next();
}

/**
 * Normalize an email address conservatively (lowercase & trim without stripping
 * valid provider dots or subaddress tags that users expect to preserve).
 * @param {string} rawEmail
 * @returns {string}
 */
function normalizeEmailAddress(rawEmail) {
  const cleaned = sanitizeText(rawEmail).toLowerCase();
  const normalized = validator.normalizeEmail(cleaned, {
    all_lowercase: true,
    gmail_lowercase: true,
    gmail_remove_dots: false,
    gmail_remove_subaddress: false,
    outlookdotcom_remove_subaddress: false,
    yahoo_remove_subaddress: false,
    icloud_remove_subaddress: false,
  });
  return normalized || cleaned;
}

/**
 * Validate and sanitize registration payload.
 * @param {unknown} payload
 * @returns {{ isValid: boolean, errors: Array<{ field: string, message: string }>, sanitized: { username: string, email: string, password: string } }}
 */
function validateRegistrationInput(payload) {
  const errors = [];

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      isValid: false,
      errors: [{ field: 'body', message: 'Request body must be a valid JSON object.' }],
      sanitized: { username: '', email: '', password: '' },
    };
  }

  const { username: rawUsername, email: rawEmail, password: rawPassword } = payload;

  // 1. Username validation & sanitization
  let cleanUsername = '';
  if (typeof rawUsername !== 'string' || rawUsername.trim().length === 0) {
    errors.push({ field: 'username', message: 'Username is required.' });
  } else {
    cleanUsername = sanitizeText(rawUsername);
    if (DANGEROUS_HTML_CHARS_REGEX.test(rawUsername) || !USERNAME_REGEX.test(cleanUsername)) {
      errors.push({
        field: 'username',
        message:
          'Username must be 3–30 characters and contain only letters, numbers, underscores, or hyphens.',
      });
    }
  }

  // 2. Email validation & normalization
  let cleanEmail = '';
  if (typeof rawEmail !== 'string' || rawEmail.trim().length === 0) {
    errors.push({ field: 'email', message: 'Email address is required.' });
  } else {
    const trimmedEmail = sanitizeText(rawEmail);
    if (DANGEROUS_HTML_CHARS_REGEX.test(trimmedEmail)) {
      errors.push({ field: 'email', message: 'Email address contains invalid characters.' });
    } else {
      cleanEmail = normalizeEmailAddress(trimmedEmail);
      if (
        cleanEmail.length > 254 ||
        !validator.isEmail(cleanEmail, { allow_utf8_local_part: false })
      ) {
        errors.push({ field: 'email', message: 'Please provide a valid email address.' });
      }
    }
  }

  // 3. Strong password policy validation (preserve intentional spaces, disallow control chars & >72 UTF-8 bytes)
  let validPassword = '';
  if (typeof rawPassword !== 'string' || rawPassword.length === 0) {
    errors.push({ field: 'password', message: 'Password is required.' });
  } else if (CONTROL_CHARS_TEST_REGEX.test(rawPassword)) {
    errors.push({
      field: 'password',
      message: 'Password contains invalid control characters.',
    });
  } else if (rawPassword.trim().length === 0) {
    errors.push({ field: 'password', message: 'Password cannot be whitespace only.' });
  } else if (rawPassword.length < 8) {
    errors.push({
      field: 'password',
      message: 'Password must be at least 8 characters long.',
    });
  } else if (Buffer.byteLength(rawPassword, 'utf8') > 72) {
    errors.push({
      field: 'password',
      message: 'Password must not exceed 72 bytes.',
    });
  } else {
    const hasUpper = /[A-Z]/.test(rawPassword);
    const hasLower = /[a-z]/.test(rawPassword);
    const hasDigit = /[0-9]/.test(rawPassword);
    const hasSpecial = /[^A-Za-z0-9\s]/.test(rawPassword);

    if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
      errors.push({
        field: 'password',
        message:
          'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.',
      });
    } else {
      validPassword = rawPassword;
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: {
      username: cleanUsername,
      email: cleanEmail,
      password: validPassword,
    },
  };
}

/**
 * Validate and sanitize login payload.
 * Accepts `identifier`, `email`, or `username` along with `password`.
 * @param {unknown} payload
 * @returns {{ isValid: boolean, errors: Array<{ field: string, message: string }>, sanitized: { identifier: string, identifierType: 'email' | 'username', password: string } }}
 */
function validateLoginInput(payload) {
  const errors = [];

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      isValid: false,
      errors: [{ field: 'body', message: 'Request body must be a valid JSON object.' }],
      sanitized: { identifier: '', identifierType: 'email', password: '' },
    };
  }

  const { identifier: rawIdentifier, email: rawEmail, username: rawUsername, password: rawPassword } =
    payload;

  let cleanIdentifier = '';
  let identifierType = 'email';

  if (rawEmail !== undefined && rawEmail !== null && String(rawEmail).length > 0) {
    if (typeof rawEmail !== 'string') {
      errors.push({ field: 'email', message: 'Email must be a string.' });
    } else {
      const trimmed = sanitizeText(rawEmail);
      if (!trimmed || DANGEROUS_HTML_CHARS_REGEX.test(trimmed) || !validator.isEmail(trimmed)) {
        errors.push({ field: 'email', message: 'Please provide a valid email address.' });
      } else {
        cleanIdentifier = normalizeEmailAddress(trimmed);
        identifierType = 'email';
      }
    }
  } else if (rawUsername !== undefined && rawUsername !== null && String(rawUsername).length > 0) {
    if (typeof rawUsername !== 'string') {
      errors.push({ field: 'username', message: 'Username must be a string.' });
    } else {
      const trimmed = sanitizeText(rawUsername);
      if (!trimmed || DANGEROUS_HTML_CHARS_REGEX.test(trimmed) || !USERNAME_REGEX.test(trimmed)) {
        errors.push({ field: 'username', message: 'Please provide a valid username.' });
      } else {
        cleanIdentifier = trimmed;
        identifierType = 'username';
      }
    }
  } else if (rawIdentifier !== undefined && rawIdentifier !== null) {
    if (typeof rawIdentifier !== 'string' || sanitizeText(rawIdentifier).length === 0) {
      errors.push({ field: 'identifier', message: 'Email or username is required.' });
    } else {
      const trimmed = sanitizeText(rawIdentifier);
      if (DANGEROUS_HTML_CHARS_REGEX.test(trimmed)) {
        errors.push({
          field: 'identifier',
          message: 'Email or username contains invalid characters.',
        });
      } else if (trimmed.includes('@')) {
        const normalized = normalizeEmailAddress(trimmed);
        if (!validator.isEmail(normalized)) {
          errors.push({ field: 'identifier', message: 'Please provide a valid email address.' });
        } else {
          cleanIdentifier = normalized;
          identifierType = 'email';
        }
      } else if (!USERNAME_REGEX.test(trimmed)) {
        errors.push({ field: 'identifier', message: 'Please provide a valid username or email.' });
      } else {
        cleanIdentifier = trimmed;
        identifierType = 'username';
      }
    }
  } else {
    errors.push({ field: 'identifier', message: 'Email or username is required.' });
  }

  let validPassword = '';
  if (typeof rawPassword !== 'string' || rawPassword.length === 0) {
    errors.push({ field: 'password', message: 'Password is required.' });
  } else if (
    CONTROL_CHARS_TEST_REGEX.test(rawPassword) ||
    Buffer.byteLength(rawPassword, 'utf8') > 72
  ) {
    errors.push({ field: 'password', message: 'Invalid password format.' });
  } else {
    validPassword = rawPassword;
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: {
      identifier: cleanIdentifier,
      identifierType,
      password: validPassword,
    },
  };
}

/**
 * Validate password against strict security policy.
 * @param {string} rawPassword
 * @param {string} [fieldName='password']
 * @returns {Array<{ field: string, message: string }>}
 */
function validatePasswordPolicy(rawPassword, fieldName = 'password') {
  const errors = [];
  if (typeof rawPassword !== 'string' || rawPassword.length === 0) {
    errors.push({ field: fieldName, message: `${fieldName} is required.` });
  } else if (CONTROL_CHARS_TEST_REGEX.test(rawPassword)) {
    errors.push({
      field: fieldName,
      message: `${fieldName} contains invalid control characters.`,
    });
  } else if (rawPassword.trim().length === 0) {
    errors.push({ field: fieldName, message: `${fieldName} cannot be whitespace only.` });
  } else if (rawPassword.length < 8) {
    errors.push({
      field: fieldName,
      message: `${fieldName} must be at least 8 characters long.`,
    });
  } else if (Buffer.byteLength(rawPassword, 'utf8') > 72) {
    errors.push({
      field: fieldName,
      message: `${fieldName} must not exceed 72 bytes.`,
    });
  } else {
    const hasUpper = /[A-Z]/.test(rawPassword);
    const hasLower = /[a-z]/.test(rawPassword);
    const hasDigit = /[0-9]/.test(rawPassword);
    const hasSpecial = /[^A-Za-z0-9\s]/.test(rawPassword);

    if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
      errors.push({
        field: fieldName,
        message:
          `${fieldName} must include at least one uppercase letter, one lowercase letter, one number, and one special character.`,
      });
    }
  }
  return errors;
}

/**
 * Validate forgot password request payload.
 * @param {unknown} payload
 */
function validateForgotPasswordInput(payload) {
  const errors = [];
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      isValid: false,
      errors: [{ field: 'body', message: 'Request body must be a valid JSON object.' }],
      sanitized: { email: '' },
    };
  }

  const { email: rawEmail } = payload;
  let cleanEmail = '';
  if (typeof rawEmail !== 'string' || rawEmail.trim().length === 0) {
    errors.push({ field: 'email', message: 'Email address is required.' });
  } else {
    const trimmed = sanitizeText(rawEmail);
    if (DANGEROUS_HTML_CHARS_REGEX.test(trimmed)) {
      errors.push({ field: 'email', message: 'Email address contains invalid characters.' });
    } else {
      cleanEmail = normalizeEmailAddress(trimmed);
      if (cleanEmail.length > 254 || !validator.isEmail(cleanEmail)) {
        errors.push({ field: 'email', message: 'Please provide a valid email address.' });
      }
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: { email: cleanEmail },
  };
}

/**
 * Validate reset password payload.
 * @param {unknown} payload
 */
function validateResetPasswordInput(payload) {
  const errors = [];
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      isValid: false,
      errors: [{ field: 'body', message: 'Request body must be a valid JSON object.' }],
      sanitized: { token: '', newPassword: '' },
    };
  }

  const { token: rawToken, newPassword: rawPassword } = payload;
  let cleanToken = '';
  if (typeof rawToken !== 'string' || rawToken.trim().length === 0) {
    errors.push({ field: 'token', message: 'Reset token is required.' });
  } else {
    cleanToken = sanitizeText(rawToken);
    if (!/^[a-f0-9]{64}$/i.test(cleanToken)) {
      errors.push({ field: 'token', message: 'Invalid token format.' });
    }
  }

  const passwordErrors = validatePasswordPolicy(rawPassword, 'newPassword');
  errors.push(...passwordErrors);

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: { token: cleanToken, newPassword: rawPassword || '' },
  };
}

/**
 * Validate change password payload.
 * @param {unknown} payload
 */
function validateChangePasswordInput(payload) {
  const errors = [];
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      isValid: false,
      errors: [{ field: 'body', message: 'Request body must be a valid JSON object.' }],
      sanitized: { currentPassword: '', newPassword: '' },
    };
  }

  const { currentPassword: rawCurrent, newPassword: rawNew } = payload;
  if (typeof rawCurrent !== 'string' || rawCurrent.length === 0) {
    errors.push({ field: 'currentPassword', message: 'Current password is required.' });
  }

  const passwordErrors = validatePasswordPolicy(rawNew, 'newPassword');
  errors.push(...passwordErrors);

  if (rawCurrent && rawNew && rawCurrent === rawNew) {
    errors.push({
      field: 'newPassword',
      message: 'New password must be different from current password.',
    });
  }

  return {
    isValid: errors.length === 0,
    errors,
    sanitized: {
      currentPassword: rawCurrent || '',
      newPassword: rawNew || '',
    },
  };
}

module.exports = {
  sanitizeText,
  escapeHtml,
  sanitizeObjectKeys,
  sanitizeRequestMiddleware,
  normalizeEmailAddress,
  validatePasswordPolicy,
  validateRegistrationInput,
  validateLoginInput,
  validateForgotPasswordInput,
  validateResetPasswordInput,
  validateChangePasswordInput,
};
