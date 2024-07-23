import User from "../models/UserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import bcrypt from 'bcrypt'
import generateToken from "../utils/generateToken.js"

// @desc Register user & get token
// @route POST api/users/
// @access Public
const registerUser = asyncHandler(async (req, res) => {
  const { name, surname, gender, dob, email, phone, password } = req.body

  // validating the inputs
  if (!name || !surname || !gender || !email || !phone || !dob || !password) {
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
    surname,
    gender,
    dob,
    email,
    phone,
    password: hashedPassword
  })

  if (user) {
    generateToken(res, user._id)

    res.status(201).json({
      _id: user._id,
      name: user.name,
      surname: user.surname,
      gender: user.gender,
      dob: user.dob,
      email: user.email,
      phone: user.phone,
      role: user.role
    })
  } else {
    res.status(400)
    throw new Error('Invalid user data.')
  }
})

// @desc login user & get token
// @route POST api/users/login
// @access Public
const loginUser = asyncHandler(async (req, res) => {

  const { email, password } = req.body
  const user = await User.findOne({ email: email })

  if (user && (await user.matchPassword(password))) {

    generateToken(res, user._id)

    res.json({
      _id: user._id,
      name: user.name,
      surname: user.surname,
      gender: user.gender,
      dob: user.dob,
      email: user.email,
      phone: user.phone,
      role: user.role
    })
  } else {
    res.status(401)
    throw new Error('Invalid credentials')
  }
})

// @desc Logout user & clear cookies
// @route POST /api/users
// @access Private
const logoutUser = asyncHandler(async(req, res) => {
  res.cookie('jwt', '', {
    httpOnly: true,
    expires: new Date(0)
  })

  res.status(200).json({message: 'User logged out'})
})


export { registerUser, loginUser, logoutUser }