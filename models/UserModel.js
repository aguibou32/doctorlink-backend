import mongoose from "mongoose"
import bcrypt from 'bcrypt'

const userSchema = mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
  },
  phone: {
    type: String,
    required: true
  },
  role: { 
    type: String, 
    enum: ['patient', 'doctor', 'admin'], 
    default: 'patient' 
  },
  password: {
    type: String, 
    required: true
  }
},
  { timestamps: true }
)

userSchema.methods.matchPassword = async function (enterredPassword) {
  return await bcrypt.compare(enterredPassword, this.password)
}

const User = mongoose.model("User", userSchema)
export default User