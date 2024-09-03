import mongoose from "mongoose"
import bcrypt from 'bcrypt'

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
},
  { timestamps: true }
)

userSchema.methods.generateVerificationToken = function () {
  const randomDigits = () => Math.floor(100000 + Math.random() * 900000).toString()
  this.verificationToken = randomDigits()
  this.verificationExpiry = Date.now() + 30 * 60 * 1000
  return this.verificationToken
}

userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password)
}

const User = mongoose.model("User", userSchema)
export default User