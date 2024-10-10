
import generateToken from "../utils/generateToken.js"
import { 
  generateAndSaveToken,
  sendVerificationTokenEmail
 } from "./utils/utils.js"
import verifyEmailSchema from "../schemas/verifyEmailSchema.js"
import resend2FACodeSchema from "../schemas/resend2FACodeSchema.js"
import resendVerificationEmailSchema from "../schemas/resendVerificationEmailSchema.js"
import TempUser from "../models/TempUserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import { verifyToken } from "./utils/utils.js"
import User from "../models/UserModel.js"
import verifyTwoFactorSchema from "../schemas/verifyTwoFactorSchema.js"
import requestIp from 'request-ip'
import { sendTwoFactorCode } from "../utils/sendEmail.js"
import resend2FACodeBySMSSchema from "../schemas/resend2FACodeBySMSSchema.js"
import twilioClient from "../utils/twilioClient.js"


// @desc Verify email
// @route POST api/users/verify-email
// @access Public
 const verifyEmail = asyncHandler(async (req, res) => {

  const { t } = req
  const { email, token } = req.body

  try {
    await verifyEmailSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }

  const tempUser = await TempUser.findOne( { email } )
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

  // Prepare the newly created user info to return (excluding sensitive data)
  const userInfo = user.toObject()
  delete userInfo._id
  delete userInfo.password

  console.log(userInfo)
  return res.status(200).json({ userInfo })
})


// @desc Resend verification email
// @route POST api/users/resend-verification-email
// @access Public
const resendVerificationEmail = asyncHandler(async (req, res) => {
  const { t } = req
  const { email } = req.body

  try {
    await resendVerificationEmailSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
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
  const newVerificationToken = await generateAndSaveToken(tempUser)

  // Update the last sent timestamp
  tempUser.lastVerificationEmailSentAt = Date.now()
  await tempUser.save()

  const emailVerificationTitle = t('emailVerificationTitle')
  const confirmEmailAddressTitle = t('confirmEmailAddressTitle')
  const greeting = t('greeting')
  const enterVerificationCodeText = t('enterVerificationCodeText')
  const verificationCodeExpiryText = t('verificationCodeExpiryText')
  const ignoreEmailText = t('ignoreEmailText')
  const thankYouText = t('thankYouText')


  // Resend verification email
  await sendVerificationTokenEmail(
    tempUser.email,
    tempUser.name,
    newVerificationToken,
    emailVerificationTitle,
    confirmEmailAddressTitle,
    greeting,
    enterVerificationCodeText,
    verificationCodeExpiryText,
    ignoreEmailText,
    thankYouText
  )

  res.status(200).json({ message: t('verificationEmailResent') })
})


// @desc Verify 2FA code and complete login
// @route POST api/users/verify-2fa
// @access Public
const verifyTwoFactor = asyncHandler(async (req, res) => {

  const { t } = req
  const { email, twoFactorCode, deviceId, deviceName } = req.body

  try {
    await verifyTwoFactorSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
  }

  const user = await User.findOne({ email })

  if (user && user.verifyTwoFactorCode(twoFactorCode)) {
    // Add the new device to the user's device list
    user.lastLogin = new Date()

    user.devices.push({
      deviceId,
      deviceName,
      lastLogin: user.lastLogin,
      clientIp: requestIp.getClientIp(req),
      isTrusted: true
    })

    await user.save()
    generateToken(res, user._id)  // Generate token after 2FA verification
    const userInfo = user.toObject()
    delete userInfo._id
    delete userInfo.password
    return res.status(200).json({ userInfo })

  } else {
    res.status(401)
    throw new Error(t('invalidTwoFactorCode'))
  }
})


// @desc Resend 2FA code by email
// @route POST api/verify-user/resend-2FA-code-by-email
// @access Public
const resend2FACodeByEmail = asyncHandler(async (req, res) => {

  const { t } = req
  const { email } = req.body

  try {
    await resend2FACodeSchema.validate(req.body, { abortEarly: false })

  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
  }

  // Find user by email
  const user = await User.findOne({ email })

  if (!user) {
    res.status(404) // Use 404 to indicate resource not found
    throw new Error(t('userNotFound'))
  }

  // Check if a 2FA code was sent within the last minute
  const oneMinuteAgo = Date.now() - 60 * 1000

  if (user.twoFactorCodeLastSent && user.twoFactorCodeLastSent > oneMinuteAgo) {
    res.status(429) // Too many requests
    throw new Error(t('verificationCodeCooldown'))
  }

  // Generate a new 2FA code
  const twoFactorCode = user.generateTwoFactorCode()
  user.twoFactorCodeLastSent = Date.now()

  // Save user after updating the timestamp
  await user.save()

  // Send 2FA code via email
  const toEmail = user.email
  const name = user.name
  const twoFactorAuthentication = t('twoFactorAuthentication')
  const twoFactorAuthenticationTitle = t('twoFactorAuthenticationTitle')
  const greeting = t('greeting')
  const twoFactorAuthenticationText = t('twoFactorAuthenticationText')
  const authenticationCode = t('authenticationCode')
  const ifNotYouText = t('ifNotYouText')
  const contactSupportText = t('contactSupportText')
  const thankYou = t('thankYou')

  sendTwoFactorCode(
    toEmail,
    twoFactorAuthentication,
    twoFactorAuthenticationTitle,
    greeting,
    name,
    twoFactorAuthenticationText,
    twoFactorCode,
    authenticationCode,
    ifNotYouText,
    contactSupportText,
    thankYou
  )
  // Return a success message
  res.status(200).json({
    message: t('twoFactorCodeSent'),
    isTwoFactorRequired: true,
    email: user.email
  })
})


// @desc Resend 2FA code by SMS
// @route POST api/users/resend-2FA-code-by-sms
// @access Public
const resend2FACodeBySMS = asyncHandler(async (req, res) => {
  const { t } = req
  const { phone } = req.body

  try {
    await resend2FACodeBySMSSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
  }

  // Find user by phone number
  const user = await User.findOne({ phone })

  if (!user) {
    res.status(404)
    throw new Error(t('userNotFound'))
  }

  // Generate a new 2FA code
  const twoFactorCode = user.generateTwoFactorCode()
  user.twoFactorCodeLastSent = Date.now()

  await user.save()

  const toPhone = user.phone
  const message = `${t('smsTwoFactorCodeMessage')} ${twoFactorCode}`;

  try {
    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: toPhone
    })
  } catch (error) {
    console.log(error)
    res.status(500)
    throw new Error(t('smsSendingFailed'))
  }

  // Return a success message
  res.status(200).json({
    message: t('twoFactorCodeSentViaSMS'),
    isTwoFactorRequired: true,
    phone: user.phone
  })
})

export {
  verifyEmail,
  resendVerificationEmail,
  verifyTwoFactor,
  resend2FACodeByEmail,
  resend2FACodeBySMS
}