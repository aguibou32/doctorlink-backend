import User from "../models/UserModel.js"
import TempUser from "../models/TempUserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import bcrypt from 'bcrypt'
import generateToken from "../utils/generateToken.js"
import { sendVerificationEmail } from "../utils/sendEmail.js"


// @desc Register user & get token
// @route POST api/users/
// @access Public
const registerUser = asyncHandler(async (req, res) => {

  const { t } = req

  const { name, surname, gender, dob, email, phone, password, terms } = req.body

  if (!terms) {
    res.status(400)
    throw new Error(t('terms_and_conditions_error'))
  }

  // Validating the inputs
  if (!name || !surname || !gender || !email || !phone || !dob || !password) {
    res.status(400)
    throw new Error(t('include_all_fields'))
  }

  // Checking if the user already exists
  const userExists = await TempUser.findOne({ email })
  if (userExists) {
    res.status(400)
    throw new Error(t('email_in_use'))
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
  })

  // Generate verification token
  const verificationToken = tempUser.generateVerificationToken()

  // Save the temporary user
  await tempUser.save()

  try {
    sendVerificationEmail(tempUser.email, tempUser.name, verificationToken)
  } catch (error) {
    res.status(400)
    throw new error('Cannot send email')
  }

  res.status(201).json({
    email: tempUser.email
  })
})

// @desc login user & get token
// @route POST api/users/login
// @access Public
const loginUser = asyncHandler(async (req, res) => {

  const { t } = req

  const { email, password } = req.body;
  const user = await User.findOne({ email: email })

  if (user && (await user.matchPassword(password))) {
    generateToken(res, user._id)

    return res.json({
      _id: user._id,
      name: user.name,
      surname: user.surname,
      gender: user.gender,
      dob: user.dob,
      email: user.email,
      phone: user.phone,
      birthPlace: user.birthPlace,
      birthCountry: user.birthCountry,
      isEmailVerified: user.isEmailVerified,
      isPhoneNumberVerified: user.isPhoneNumberVerified,
      role: user.role
    })

  } else {
    res.status(401);
    throw new Error(t('invalid_credentials'))
  }
})

// @desc Verify email
// @route GET api/users/verify-email
// @access Public
const verifyEmail = asyncHandler(async (req, res) => {

  const { email, token } = req.body

  // console.log(token)
  const tempUser = await TempUser.findOne({ email: email, verificationToken: token })

  if (!tempUser) {
    res.status(400)
    throw new Error(t('invalidOrExpiredToken'))
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
    message: ''
  })
})

// @desc Resend verfication email
// @route POST api/users/resend-verification-email
// @access Public
const resendVerificationEmail = asyncHandler(async (req, res) => {

  const { email } = req.body

  if (!email) {
    res.status(400)
    throw new Error(t('pleaseProvideEmail'))
  }

  const tempUser = await TempUser.findOne({ email })

  // Check if there is a user with this email
  if (!tempUser) {
    res.status(400)
    throw new Error(t('userNotFoundOrAlreadyVerified'))
  }

  // Generate verification token
  const newVerificationToken = tempUser.generateVerificationToken()

  tempUser.verificationToken = newVerificationToken
  tempUser.save()

  try {
    sendVerificationEmail(tempUser.email, tempUser.name, newVerificationToken)
  } catch (error) {
    res.status(400)
    throw new error(t('cannotSendEmail'))
  }

  res.status(200).json({ message: t('verificationEmailResent') })
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


// @desc Update user 
// @route PUT /api/users/update
// @access Private
const updateUserProfile = asyncHandler(async (req, res) => {

  const { t } = req
  const user = await User.findById(req.user.id)


  if (user) {

    user.name = req.body.name || user.name
    user.surname = req.body.surname || user.surname
    user.gender = req.body.gender || user.gender
    user.dob = req.body.dob || user.dob
    user.email = req.body.email || user.email
    user.phone = req.body.phone || user.phone
    user.birthPlace = req.body.birthPlace || user.birthPlace
    user.birthCountry = req.body.birthCountry || user.birthCountry

    if (req.body.password) {
      const salt = await bcrypt.genSalt(10)
      const password = req.body.password
      const hashedPassword = await bcrypt.hash(password, salt)
      user.password = hashedPassword
    }

    await new Promise((resolve) => setTimeout(resolve, 5000))

    const updatedUser = await user.save()

    res.status(200).json({
      message: t('userUpdatedSuccessfully'),
      user: {
        _id: updatedUser._id,
        name: updatedUser.name,
        surname: updatedUser.surname,
        gender: updatedUser.gender,
        dob: updatedUser.dob,
        email: updatedUser.email,
        phone: updatedUser.phone,
        birthPlace: updatedUser.birthPlace,
        birthCountry: updatedUser.birthCountry
      }
    })

  } else {
    res.status(404)
    throw new Error(t('userNotFound'))
  }
})

export {
  registerUser,
  loginUser,
  verifyEmail,
  resendVerificationEmail,
  updateUserProfile,
  logoutUser
}
