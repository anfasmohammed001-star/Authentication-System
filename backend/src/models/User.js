const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required.'],
      trim: true,
      minlength: [3, 'Username must be at least 3 characters.'],
      maxlength: [30, 'Username must not exceed 30 characters.'],
      match: [
        /^[a-zA-Z0-9_-]{3,30}$/,
        'Username may only contain letters, numbers, underscores, and hyphens.',
      ],
    },
    usernameNormalized: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      select: false,
    },
    email: {
      type: String,
      required: [true, 'Email address is required.'],
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: [254, 'Email address must not exceed 254 characters.'],
    },
    passwordHash: {
      type: String,
      required: [true, 'Password hash is required.'],
      select: false, // Never return password hashes in standard queries
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
      default: null,
    },
    passwordResetTokenHash: {
      type: String,
      select: false,
      default: null,
    },
    passwordResetExpiresAt: {
      type: Date,
      select: false,
      default: null,
    },
    passwordChangedAt: {
      type: Date,
      default: null,
    },
    tokenVersion: {
      type: Number,
      default: 0,
    },
    createdAt: {
      type: Date,
      default: Date.now,
      immutable: true,
    },
  },
  {
    timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' },
    versionKey: false,
  }
);

// Automatically populate normalized username prior to validation
userSchema.pre('validate', function normalizeFields(next) {
  if (this.username && typeof this.username === 'string') {
    this.username = this.username.trim();
    this.usernameNormalized = this.username.toLowerCase();
  }
  if (this.email && typeof this.email === 'string') {
    this.email = this.email.trim().toLowerCase();
  }
  next();
});

// Strip sensitive/internal properties whenever serialized
function transformUserDoc(_doc, ret) {
  ret.id = ret._id ? ret._id.toString() : undefined;
  delete ret._id;
  delete ret.passwordHash;
  delete ret.passwordResetTokenHash;
  delete ret.passwordResetExpiresAt;
  delete ret.usernameNormalized;
  delete ret.__v;
  return ret;
}

userSchema.set('toJSON', { transform: transformUserDoc });
userSchema.set('toObject', { transform: transformUserDoc });

const User = mongoose.model('User', userSchema);

module.exports = User;

