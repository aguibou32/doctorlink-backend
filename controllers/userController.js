import User from "../models/UserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import bcrypt from 'bcrypt'
import generateToken from "../utils/generateToken.js"

// @desc Register user & get token
// @route POST api/users/
// @access Public
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, phone, dob, password } = req.body

  // validating the inputs
  if (!name || !email || !phone || !dob || !password) {
    res.status(400)
    throw new Error('Please include all fields')
  }

  // Checking if the user already
  const userExists = await User.findOne({ email })
  if (userExists) {
    res.status(400)
    throw new Error('User already exists !')
  }

  // Hashing the pwd
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  // Creating the user
  const user = await User.create({
    name,
    email,
    phone,
    dob,
    password: hashedPassword
  })

  if(user){
    generateToken(res, user._id)

    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      dob: user.dob,
      role: user.role
    })
  }else{
    res.status(400)
    throw new Error('Invalid user data.')
  }
})

export {registerUser}