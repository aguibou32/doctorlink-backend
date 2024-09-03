import User from "../models/UserModel.js"
import TempUser from "../models/TempUserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import bcrypt from 'bcrypt'
import generateToken from "../utils/generateToken.js"
import { sendVerificationEmail } from "../utils/sendEmail.js"

const generateAndSaveToken = async (user, userType) => {
  const verificationToken = user.generateVerificationToken()

  if (userType === 'tempUser') {
    await user.save() 
  } else if (userType === 'user') {
    await user.save({ timestamps: false }) // Not changing this to avoid side effects
  }
  return verificationToken
}


// Helper function to send verification email to both 
// TempUser or regular User (DRY principle)
const sendVerificationTokenEmail = async (email, name, token, t) => {
  try {
    await sendVerificationEmail(email, name, token) // Removed t if not needed
  } catch (error) {
    throw new Error(t('cannotSendEmail'))
  }
}

// Helper function to verify token for TempUser or regular User
const verifyToken = (user, token, t) => {
  if (!user) throw new Error(t('userNotFound'))
  if (user.verificationToken !== token) throw new Error(t('invalidToken'))
  if (user.verificationExpiry && Date.now() > user.verificationExpiry) throw new Error(t('expiredToken'))
}

// @desc Check if email is in use
// @route POST api/users/check-email-in-use
// @access Public
const checkEmailInUse = asyncHandler (async (req, res) => {

  const { t } = req
  const { email } = req.body

  if(!email) {
    res.status(400)
    throw new Error(t('emailRequired'))
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

  if (!emailRegex.test(email)) {
    res.status(400);
    throw new Error(t('invalidEmailFormat'))
  }

  const emailInUse = await User.findOne({ email })

  if(emailInUse){
    res.status(400)
    throw new Error(t('emailInUse'))
  }else {
    res.status(200).json({ message: t('emailAvailable') })
  }
})

// @desc Check if phone number is in use
// @route POST api/users/check-phone-in-use
// @access Public
const checkPhoneInUse = asyncHandler( async (req, res) => {
  const { t } = req
  const { phone } = req.body

  if(!phone){
    res.status(400)
    throw new Error(t('phoneRequired'))
  }
  
  const phoneInUse = await User.findOne( { phone })
  
  if(phoneInUse){
    res.status(400)
    throw new Error('phoneInUse')
  }else{
    res.json(200).json({ message: t('phoneAvailable') })
  }
})

// @desc Register user & get token
// @route POST api/users/
// @access Public
const registerUser = asyncHandler(async (req, res) => {
  const { t } = req
  const { name, surname, gender, dob, email, phone, password, terms } = req.body

  if (!terms) {
    res.status(400)
    throw new Error(t('termsAndConditionsError'))
  }

  if (!name || !surname || !gender || !email || !phone || !dob || !password) {
    res.status(400)
    throw new Error(t('includeAllFields'))
  }

  const userExists = await TempUser.findOne({ email })
  if (userExists) {
    await userExists.deleteOne()
  }

  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  const tempUser = new TempUser({
    name,
    surname,
    gender,
    email,
    phone,
    dob,
    password: hashedPassword,
  })

  const verificationToken = await generateAndSaveToken(tempUser, 'tempUser')
  // when we call generateAndSaveToken, we are already saving the user, that's why we not saving the user
  // again in the try catch block

  try {
    await sendVerificationTokenEmail(tempUser.email, tempUser.name, verificationToken, t)
    tempUser.lastVerificationEmailSentAt = Date.now()
    await tempUser.save()
    res.status(201).json({ email: tempUser.email })
  } catch (error) {
    res.status(500)
    throw new Error(t('cannotSendEmail'))
  }
})

// @desc Verify email
// @route POST api/users/verify-email
// @access Public
const verifyEmail = asyncHandler(async (req, res) => {
  const { t } = req
  const { email, token } = req.body

  const tempUser = await TempUser.findOne({ email })
  verifyToken(tempUser, token, t)

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

  // Delete temporary user
  await tempUser.deleteOne()

  // Generate token for user session (to log in the user)
  generateToken(res, user._id)

  const userResponse = { // We sending back a a new user, excluding the pwd
    name: user.name,
    surname: user.surname,
    gender: user.gender,
    dob: user.dob,
    email: user.email,
    phone: user.phone,
    isEmailVerified: true,
  }

  res.status(200).json(userResponse)
})

// @desc Resend verification email
// @route POST api/users/resend-verification-email
// @access Public
const resendVerificationEmail = asyncHandler(async (req, res) => {
  const { t } = req
  const { email } = req.body

  if (!email) {
    res.status(400)
    throw new Error(t('pleaseProvideEmail'))
  }

  const tempUser = await TempUser.findOne({ email })
  if (!tempUser) {
    res.status(400)
    throw new Error(t('userNotFoundOrAlreadyVerified'))
  }

  // Check if last email was sent within the last minute
  const oneMinuteAgo = Date.now() - 60 * 1000
  if (tempUser.lastVerificationEmailSentAt && tempUser.lastVerificationEmailSentAt > oneMinuteAgo) {
    res.status(429)
    throw new Error(t('verificationEmailCooldown'))
  }

  // Generate and save new verification token
  const newVerificationToken = await generateAndSaveToken(tempUser, 'tempUser')

  // Update the last sent timestamp
  tempUser.lastVerificationEmailSentAt = Date.now()
  await tempUser.save()

  // Resend verification email
  await sendVerificationTokenEmail(tempUser.email, tempUser.name, newVerificationToken, t)

  res.status(200).json({ message: t('verificationEmailResent') })
})

// @desc Login user & get token
// @route POST api/users/login
// @access Public
const loginUser = asyncHandler(async (req, res) => {
  const { t } = req
  const { email, password } = req.body

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
    res.status(401)
    throw new Error(t('invalidCredentials'))
  }
})

// @desc Logout user & clear cookies
// @route POST /api/users/logout
// @access Private
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie('jwt', '', {
    httpOnly: true,
    expires: new Date(0)
  })
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
        isEmailVerified: updatedUser.isEmailVerified,
        isPhoneNumberVerified: updatedUser.isPhoneNumberVerified,
        birthPlace: updatedUser.birthPlace,
        birthCountry: updatedUser.birthCountry
      }
    })

  } else {
    res.status(404)
    throw new Error(t('userNotFound'))
  }
})

// @desc Send verification email for email change
// @route POST api/users/sendEmailChangeVerification
// @access Private
const sendEmailChangeVerification = asyncHandler(async (req, res) => {
  const { t } = req
  const user = await User.findById(req.user.id)
  const { newEmail } = req.body

  if (user.email === newEmail) {
    throw new Error(t("newEmailCurrentEmail"))
  }

  // Check if last email was sent within the last minute
  const oneMinuteAgo = Date.now() - 60 * 1000
  if (user.lastVerificationEmailSentAt && user.lastVerificationEmailSentAt > oneMinuteAgo) {
    res.status(429)
    throw new Error(t('verificationEmailCooldown'))
  }

  const verificationToken = await generateAndSaveToken(user, 'user')
  // Try to send verification email
  try {
    await sendVerificationTokenEmail(newEmail, user.name, verificationToken, t)
    user.lastVerificationEmailSentAt = Date.now()
    await user.save()

    res.status(201).json({ email: newEmail })
  } catch (error) {
    res.status(500)
    throw new Error(t('cannotSendEmail'))
  }
})


// @desc Resend verification email for email change
// @route POST api/users/resend-email-change-verification
// @access Private
const resendEmailChangeVerification = asyncHandler(async (req, res) => {
  const { t } = req
  const user = await User.findById(req.user.id)
  const { newEmail } = req.body



  if (!newEmail) {
    res.status(400)
    throw new Error(t('pleaseProvideEmail'))
  }

  if (user.email === newEmail) {
    throw new Error(t("newEmailCurrentEmail"))
  }

  // Check if last email was sent within the last minute
  const oneMinuteAgo = Date.now() - 60 * 1000
  if (user.lastVerificationEmailSentAt && user.lastVerificationEmailSentAt > oneMinuteAgo) {
    res.status(429)
    throw new Error(t('verificationEmailCooldown'))
  }

  // Generate and save new verification token
  const newVerificationToken = await generateAndSaveToken(user, 'user')

  // Update the last sent timestamp
  user.lastVerificationEmailSentAt = Date.now()
  await user.save()

  // Resend verification email
  await sendVerificationTokenEmail(newEmail, user.name, newVerificationToken, t)

  res.status(200).json({ message: t('verificationEmailResent') })
})

// @desc Verify user token for email change
// @route POST api/users/verifyEmailChange
// @access Private
const verifyEmailChange = asyncHandler(async (req, res) => {

  // console.log(req.body)

  const { t } = req
  const { newEmail, token } = req.body
  
  const user = await User.findById(req.user.id)
  verifyToken(user, token, t)

  // Update the email and clear the verification token and expiry
  user.email = newEmail
  user.verificationToken = undefined
  user.verificationExpiry = undefined

  await user.save()

  // console.log(user)

  res.status(200).json({
    message: t("emailAddressUpdated"),
    email: user.email
  })
})

export {
  checkEmailInUse,
  checkPhoneInUse,
  registerUser,
  verifyEmail,
  resendVerificationEmail,
  loginUser,
  logoutUser,
  updateUserProfile,
  sendEmailChangeVerification,
  resendEmailChangeVerification,
  verifyEmailChange
}
