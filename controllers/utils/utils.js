import { 
  sendVerificationEmail,
 } from "../../utils/sendEmail.js"

import asyncHandler from "../../middleware/asyncHandler.js"
import phoneInUseSchema from "../../schemas/phoneInUseSchema.js"
import emailInUseSchema from "../../schemas/emailInUseSchema.js"

import User from "../../models/UserModel.js"

// @desc Check if email is in use
// @route POST api/users/check-email-in-use
// @access Public
export const checkEmailInUse = asyncHandler(async (req, res) => {

  const { t } = req
  const { email } = req.body

  try {
    await emailInUseSchema.validate({ email }, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }

  // I want the search to return true for any variant of test@email.com (e.g Test@email.com)
  const emailInUse = await User.findOne({ email: { $regex: `^${email}$`, $options: 'i' } })

  if (emailInUse) {
    res.status(400)
    throw new Error(t('emailInUse'))
  } else {
    res.status(200).json({ message: t('emailAvailable') })
  }
})


// @desc Check if phone number is in use
// @route POST api/users/check-phone-in-use
// @access Public
  export const checkPhoneInUse = asyncHandler(async (req, res) => {
  const { t } = req
  const { phone } = req.body

  try {
    await phoneInUseSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }

  const phoneInUse = await User.findOne({ phone })

  if (phoneInUse) {
    res.status(400)
    throw new Error(t('phoneInUse'))
  } else {
    res.status(200).json({ message: t('phoneAvailable') })
  }
})

 // Helper function to use User or Temp model function generateVerificationToken() 
 // to generate and save token to database
 export const generateAndSaveCode = async user => {
  if (user.userVerificationRateLimit <= 0) {
    throw new Error(t('verificationRateLimitError'))
  }
  const verificationCode = await user.generateVerificationCode()

  user.userVerificationRateLimit -= 1
  await user.save()
  
  return verificationCode
}

// Helper function to send verification email to both 
// TempUser or regular User (DRY principle)
export const sendVerificationCodeEmail = async (
  email,
  name,
  verificationCode,
  emailVerificationTitle,
  confirmEmailAddressTitle,
  greeting,
  enterVerificationCodeText,
  verificationCodeExpiryText,
  ignoreEmailText,
  thankYouText

) => {
  try {
    await sendVerificationEmail(
      email,
      name,
      verificationCode,
      emailVerificationTitle,
      confirmEmailAddressTitle,
      greeting,
      enterVerificationCodeText,
      verificationCodeExpiryText,
      ignoreEmailText,
      thankYouText

    ) // Removed t if not needed
  } catch (error) {
    throw new Error(t('cannotSendEmail'))
  }
}

// Helper function to verify token for TempUser or regular User
export const verifyCode = (user, token, t) => {
  if (!user) throw new Error(t('userNotFound'))
  if (user.verificationCode !== token) throw new Error(t('invalidToken'))
  if (user.verificationExpiry && Date.now() > user.verificationExpiry) throw new Error(t('expiredToken'))
}

