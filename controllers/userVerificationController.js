import generateToken from "../utils/generateToken.js"
import verifyEmailSchema from "../schemas/verifyEmailSchema.js"
import resend2FACodeSchema from "../schemas/resend2FACodeSchema.js"
import resendVerificationEmailSchema from "../schemas/resendVerificationEmailSchema.js"
import TempUser from "../models/TempUserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import User from "../models/UserModel.js"
import verifyTwoFactorSchema from "../schemas/verifyTwoFactorSchema.js"
import { sendTwoFactorCode } from "../utils/sendEmail.js"
import send2FACodeBySMSSchema from "../schemas/send2FACodeBySMSSchema.js"
import sendEmailChangeVerificationSchema from "../schemas/sendEmailChangeVerificationSchema.js"
import twilioClient from "../utils/twilioClient.js"
import requestIp from 'request-ip'

import {
  generateAndSaveCode,
  sendVerificationCodeEmail,
  verifyCode,
} from "./utils/utils.js"

// @desc Verify email
// @route POST api/users/verify-email
// @access Public
const verifyEmail = asyncHandler(async (req, res) => {

  const { t } = req
  const { email, verificationCode } = req.body

  try {
    await verifyEmailSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }

  const tempUser = await TempUser.findOne({ email })
  verifyCode(tempUser, token, t)

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
  delete userInfo.devices // If too many devices, it makes the cookie too long and the max for a cookie is 4096 bytes 

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

  // Check if the verification rate is not reached
  if(tempUser.userVerificationRateLimit === 5){
    res.status(429)
    throw new Error('rateLimiReached')
  }

  // Check if last email was sent within the last minute
  const oneMinuteAgo = Date.now() - 60 * 1000
  if (tempUser.lastVerificationEmailSentAt && tempUser.lastVerificationEmailSentAt > oneMinuteAgo) {
    res.status(429)
    throw new Error(t('verificationEmailCooldown'))
  }

  // Generate and save new verification token
  const newVerificationToken = await generateAndSaveCode(tempUser)

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
  await sendVerificationCodeEmail(
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

  // Verify the provided token
  const isTokenValid = user.verifyTwoFactorCode(twoFactorCode)
  if (!isTokenValid) {
    res.status(401) // 401 Unauthorized for invalid token
    throw new Error(t('invalidOrExpiredToken'))
  }

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
// @route POST api/verify-user/resend-2FA-code-by-sms
// @access Public
const send2FACodeBySMS = asyncHandler(async (req, res) => {

  const { t } = req
  const { email, phone } = req.body

  try {
    await send2FACodeBySMSSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
  }

  // Find user by phone number
  const user = await User.findOne({ email })

  if (!user) {
    res.status(404)
    throw new Error(t('userNotFound'))
  }

  // Preventing spam
  const cooldownPeriod = 60 * 1000
  if (Date.now() - user.twoFactorCodeLastSent < cooldownPeriod) {
    res.status(429)
    throw new Error(t('waitBeforeRequestingCodeAgain'))
  }

  // Generate a new 2FA code
  const twoFactorCode = user.generateTwoFactorCode()
  user.twoFactorCodeLastSent = Date.now()

  await user.save()

  const message = `${t('smsTwoFactorCodeMessage')} ${twoFactorCode}. ${t('twoFactorCodeExpiry')}.`

  try {
    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone
    })
  } catch (error) {
    console.error('Twilio error:', error)
    if (error.code === 21608) {  // Invalid phone number
      res.status(400)
      throw new Error(t('invalidPhoneNumber'))
    }
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

// @desc Resend 2FA code by SMS
// @route POST api/verify-user/resend-2FA-code-by-sms
// @access Public
const resend2FACodeBySMS = asyncHandler(async (req, res) => {

  const { t } = req
  const { email, phone } = req.body

  try {
    await send2FACodeBySMSSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
  }

  // Find user by phone number
  const user = await User.findOne({ email })

  if (!user) {
    res.status(404)
    throw new Error(t('userNotFound'))
  }

  // Preventing spam
  const cooldownPeriod = 60 * 1000
  if (Date.now() - user.twoFactorCodeLastSent < cooldownPeriod) {
    res.status(429)
    throw new Error(t('waitBeforeRequestingCodeAgain'))
  }

  // Generate a new 2FA code
  const twoFactorCode = user.generateTwoFactorCode()
  user.twoFactorCodeLastSent = Date.now()

  await user.save()

  const message = `${t('smsTwoFactorCodeMessage')} ${twoFactorCode}. ${t('twoFactorCodeExpiry')}.`

  try {
    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone
    })
  } catch (error) {
    console.error('Twilio error:', error)
    if (error.code === 21608) {  // Invalid phone number
      res.status(400)
      throw new Error(t('invalidPhoneNumber'))
    }
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


// @desc Verify user token for current phone or phone change
// @route POST api/users/verify-phone-number
// @access Private
const verifyPhoneNumber = asyncHandler(async (req, res) => {

  const { t } = req
  const { phone, twoFactorCode } = req.body

  // Find the user by ID
  const user = await User.findById(req.user.id)
  if (!user) {
    res.status(404)
    throw new Error(t('userNotFound'))
  }

  // Check if the phone is already verified
  if (phone === user.phone && user.isPhoneNumberVerified) {
    res.status(400)
    throw new Error(t('phoneNumberAlreadyVerified'))
  }

  // Verify the provided token
  const isTwoFactorCodeValid = user.verifyTwoFactorCode(twoFactorCode)
  if (!isTwoFactorCodeValid) {
    res.status(401) // 401 Unauthorized for invalid token
    throw new Error(t('invalidOrExpiredToken'))
  }

  // Update phone number and verification status
  user.phone = phone
  user.isPhoneNumberVerified = true
  user.twoFactorCode = undefined
  user.twoFactorExpiry = undefined

  // Save user data
  await user.save()

  // Send success response
  res.status(200).json({
    message: t('phoneNumberUpdated'),
    email: user.email,
  })
})


// @desc Send verification email for email changeß
// @route POST api/verify-user/sendEmailChangeVerification
// @access Private
const sendEmailChangeVerification = asyncHandler(async (req, res) => {

  const { t } = req
  const user = await User.findById(req.user.id)
  const { newEmail } = req.body

  try {
    await sendEmailChangeVerificationSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
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

  const verificationToken = await generateAndSaveToken(user)
  // Try to send verification email

  const emailVerificationTitle = t('emailVerificationTitle')
  const confirmEmailAddressTitle = t('confirmEmailAddressTitle')
  const greeting = t('greeting')
  const enterVerificationCodeText = t('enterVerificationCodeText')
  const verificationCodeExpiryText = t('verificationCodeExpiryText')
  const ignoreEmailText = t('ignoreEmailText')
  const thankYouText = t('thankYouText')

  try {
    await sendVerificationTokenEmail(
      newEmail, user.name,
      verificationToken,
      emailVerificationTitle,
      confirmEmailAddressTitle,
      greeting,
      enterVerificationCodeText,
      verificationCodeExpiryText,
      ignoreEmailText,
      thankYouText
    )
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

  try {
    await sendEmailChangeVerificationSchema.validate(req.body, { abortEarly: false })

  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
  }


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
  const newVerificationToken = await generateAndSaveToken(user)

  // Update the last sent timestamp
  user.lastVerificationEmailSentAt = Date.now()
  await user.save()

  const emailVerificationTitle = t('emailVerificationTitle')
  const confirmEmailAddressTitle = t('confirmEmailAddressTitle')
  const greeting = t('greeting')
  const enterVerificationCodeText = t('enterVerificationCodeText')
  const verificationCodeExpiryText = t('verificationCodeExpiryText')
  const ignoreEmailText = t('ignoreEmailText')
  const thankYouText = t('thankYouText')

  // Resend verification email
  await sendVerificationTokenEmail(
    newEmail,
    user.name,
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

// @desc Verify user token for email change
// @route POST api/users/verifyEmailChange
// @access Private
const verifyEmailChange = asyncHandler(async (req, res) => {

  const { t } = req
  const { newEmail, token } = req.body

  const user = await User.findById(req.user.id)
  verifyToken(user, token, t)

  // Update the email and clear the verification token and expiry
  user.email = newEmail
  user.isEmailVerified = true
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
  verifyEmail,
  send2FACodeBySMS,
  resendVerificationEmail,
  verifyTwoFactor,
  resend2FACodeByEmail,
  resend2FACodeBySMS,
  sendEmailChangeVerification,
  resendEmailChangeVerification,
  verifyEmailChange,
  verifyPhoneNumber
}