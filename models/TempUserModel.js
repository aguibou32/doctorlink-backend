import mongoose from "mongoose"
import bcrypt from 'bcrypt'

const tempUserSchema = new mongoose.Schema({
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
    required: true
  },
  role: {
    type: String,
    enum: ['patient', 'practician', 'admin'],
    default: 'patient'
  },
  password: {
    type: String,
    required: true
  },
  verificationToken: {
    type: String,
  },
  lastVerificationEmailSentAt: {
    type: Date,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: { expires: '1m' }
  }
}, 
{ timestamps: true })

tempUserSchema.methods.generateVerificationToken = function() {
  const randomDigits = () => Math.floor(100000 + Math.random() * 900000).toString()
  this.verificationToken = randomDigits()
  return this.verificationToken
}

tempUserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password)
}

const TempUser = mongoose.model("TempUser", tempUserSchema)
export default TempUser