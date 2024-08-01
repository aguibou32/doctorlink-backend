import User from "../models/UserModel.js"
import TempUser from "../models/TempUserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import bcrypt from 'bcrypt'
import generateToken from "../utils/generateToken.js"
import sendEmail from "../utils/sendEmail.js"

// @desc Register user & get token
// @route POST api/users/
// @access Public
const registerUser = asyncHandler(async (req, res) => {
  const { name, surname, gender, dob, email, phone, password } = req.body

  // Validating the inputs
  if (!name || !surname || !gender || !email || !phone || !dob || !password) {
    res.status(400)
    throw new Error('Please include all fields!')
  }

  // Checking if the user already exists
  const userExists = await User.findOne({ email })
  if (userExists) {
    res.status(400);
    throw new Error('User already exists!')
  }

  // Hashing the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt)

  // Creating the temporary user
  const tempUser = new TempUser({
    name,
    surname,
    gender,
    dob,
    email,
    phone,
    password: hashedPassword
  });

  // Generate verification token
  const verificationToken = tempUser.generateVerificationToken()

  // Save the temporary user
  await tempUser.save()

  // Send verification email
  const verificationUrl = `${req.protocol}://${req.get('host')}/api/users/verify-email?token=${verificationToken}`
  await sendEmail({
    to: tempUser.email,
    subject: 'Email Verification',
    text: `Please verify your email by clicking the link: ${verificationUrl}`
  });

  res.status(201).json({
    email: tempUser.email
  });
});

// @desc login user & get token
// @route POST api/users/login
// @access Public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email })

  if (user && (await user.matchPassword(password))){
    generateToken(res, user._id)

    return res.json({
      _id: user._id,
      name: user.name,
      surname: user.surname,
      gender: user.gender,
      dob: user.dob,
      email: user.email,
      phone: user.phone,
      role: user.role
    });
  } else {
    res.status(401);
    throw new Error('Invalid credentials.')
  }
});

// @desc Verify email
// @route GET api/users/verify-email
// @access Public
const verifyEmail = asyncHandler(async (req, res) => {

  const { token } = req.body

  console.log(token)

  const tempUser = await TempUser.findOne({ verificationToken: token })

  if (!tempUser) {
    res.status(400)
    throw new Error('Token invalide ou expiré.')
  }

  // Create a user that is permanent
  const user = await User.create({
    name: tempUser.name,
    surname: tempUser.surname,
    gender: tempUser.gender,
    dob: tempUser.dob,
    email: tempUser.email,
    phone: tempUser.phone,
    isEmailVerified: true,
    password: tempUser.password
  })

  // Delete the temporary user
  await tempUser.deleteOne()

  // Generate the token that will log in the user
  generateToken(res, user._id)
  res.status(200).json({
    _id: user._id,
    name: user.name,
    surname: user.surname,
    gender: user.gender,
    dob: user.dob,
    email: user.email,
    phone: user.phone,
    role: user.role,
    message: 'Email verified successfully'
  })
})

// @desc Resend verfication email
// @route POST api/users/resend-verification-email
// @access Public
const resendVerificationEmail = asyncHandler( async (req, res) => {

  const { email } = req.body

  if(!email){
    res.status(400)
    throw new Error('Veuillez fournir un email.')
  }

  const tempUser = await TempUser.findOne({ email })

  // Check if there is a user with this email
  if(!tempUser){
    res.status(400)
    throw new Error('Utilisateur introuvable ou deja verifié.')
  }

  // Generate verification token
  const newVerificationToken = tempUser.generateVerificationToken()

  tempUser.verificationToken = newVerificationToken
  tempUser.save()
  
  const verificationUrl = `${req.protocol}://${req.get('host')}/api/users/verify-email?token=${newVerificationToken}`

  await sendEmail({
    to: tempUser.email,
    subject: 'Email verification',
    text: `Please verify your email by clicking the link: ${verificationUrl}`
  })


  res.status(200).json({message: 'Email de verification renvoyé.'})
})


// @desc Logout user & clear cookies
// @route POST /api/users/logout
// @access Private
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie('jwt', '', {
    httpOnly: true,
    expires: new Date(0)
  });
  res.status(200).json({ message: 'User logged out' })
})

export { registerUser, loginUser, verifyEmail, resendVerificationEmail, logoutUser }
