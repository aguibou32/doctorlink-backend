import mongoose from "mongoose"  
import bcrypt from 'bcrypt'  
import crypto from 'crypto'  

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  surname: {
    type: String,
    required: true
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other']
  },
  dob: {
    type: Date,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  phone: {
    type: String,
    required: true,
    unique: true
  },
  birthPlace: {
    type: String,
  },
  birthCountry: {
    type: String,
  },
  role: {
    type: String,
    enum: ['patient', 'doctor', 'admin'],
    default: 'patient'
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  isPhoneNumberVerified: {
    type: Boolean,
    default: false
  },
  password: {
    type: String,
    required: true
  },
  verificationToken: {
    type: String,
  },
  verificationExpiry: {
    type: Date,
  },
  lastVerificationEmailSentAt: {
    type: Date,
  },
  resetPasswordToken: {
    type: String,
  },
  resetPasswordExpiry: {
    type: Date,
  },
  lastResetPasswordEmailSentAt: {
    type: Date,
  },
  devices: [{
    deviceId: String, 
    deviceName: String,  
    lastLogin: Date,
    clientIp: String,  
    isTrusted: { type: Boolean, default: false },  
  }],
  isTwoFactorEnabled: {  
    type: Boolean,
    default: true,
  },
  twoFactorCode: {  
    type: String,
  },
  twoFactorCodeLastSent: {  
    type: Date,
  },
  twoFactorExpiry: { 
    type: Date,
  },
}, { timestamps: true })  

// Generate verification token (2FA)
userSchema.methods.generateVerificationToken = function () {
  const randomDigits = () => Math.floor(100000 + Math.random() * 900000).toString()  
  this.verificationToken = randomDigits()  
  this.verificationExpiry = Date.now() + 30 * 60 * 1000
  return this.verificationToken  
}

// Generate 2FA code
userSchema.methods.generateTwoFactorCode = function () {
  const randomDigits = () => Math.floor(100000 + Math.random() * 900000).toString()  
  this.twoFactorCode = randomDigits()  
  this.twoFactorExpiry = Date.now() + 30 * 60 * 1000  
  return this.twoFactorCode  
}  

// Verify the 2FA code
userSchema.methods.verifyTwoFactorCode = function (enteredCode) {
  return enteredCode === this.twoFactorCode && Date.now() < this.twoFactorExpiry  
}  

// Generate reset password token
userSchema.methods.generateResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex')  
  this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex')  
  this.resetPasswordExpiry = Date.now() + 30 * 60 * 1000    
  return resetToken  
}  

// Match password for login
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password)  
}  

const User = mongoose.model("User", userSchema)  
export default User  