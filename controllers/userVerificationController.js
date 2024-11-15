import generateToken from "../utils/generateToken.js"
import verifyEmailSchema from "../schemas/verifyEmailSchema.js"
import asyncHandler from "../middleware/asyncHandler.js"
import User from "../models/UserModel.js"
import send2FACodeBySMSSchema from "../schemas/send2FACodeBySMSSchema.js"
import twilioClient from "../utils/twilioClient.js"
import requestIp from 'request-ip'

import resendVerificationEmailSchema from '../schemas/resendVerificationEmailSchema.js'
import { generateAndSaveCode } from "./utils/utils.js"
import { sendVerificationEmail } from "../utils/sendEmail.js"

import {
  verifyCode,
} from "./utils/utils.js"

// @desc Verify email
// @route POST api/users/verify-email
// @access Public
const verifyEmail = asyncHandler(async (req, res) => {

  const { t } = req
  const { email, verificationCode, deviceId, deviceName } = req.body

  try {
    await verifyEmailSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed.')
  }

  const user = await User.findOne({ email })
  if (!user) {
    res.status(404)
    throw new Error(t('userNotFound'))
  }
  
  verifyCode(user, verificationCode, t)

  const clientIp = requestIp.getClientIp(req)

  // Check if device already exists
  const isKnownDevice = user.devices.some(device =>
    device.deviceId === deviceId &&
    device.deviceName === deviceName &&
    device.clientIp === clientIp
  )
  if (!isKnownDevice) {
    user.devices.push({
      deviceId,
      deviceName,
      lastLogin: user.lastLogin,
      clientIp: clientIp,
      isTrusted: true
    })
  } else {
    isKnownDevice.lastLogin = user.lastLogin
  }

  user.isEmailVerified = true // Because regardless of the circumtance, the email has been verifiied
  user.lastLogin = new Date()
  user.verificationCode = undefined
  user.verificationExpiry = undefined
  await user.save()

  generateToken(res, user._id)

  // Prepare the newly created user info to return (excluding sensitive data)
  const userInfo = user.toObject()
  delete userInfo._id
  delete userInfo.password
  delete userInfo.devices

  return res.status(200).json({ userInfo, message: t('userVerifiedLoginSuccess') })
})

// @desc Resend verification email to user
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

  const user = await User.findOne({ email })
  if (!user) {
    res.status(400)
    throw new Error(t('userNotFound'))
  }

  // One-minute cooldown check
  const oneMinuteAgo = Date.now() - 60 * 1000
  if (user.lastVerificationEmailSentAt && user.lastVerificationEmailSentAt > oneMinuteAgo) {
    throw new Error(t('verificationEmailCooldown'))
  }

  // Generate and save new verification token
  const newVerificationCode = await generateAndSaveCode(user, t)

    const emailVerificationTitle =  t('emailVerificationTitle')
    const confirmEmailAddressTitle =  t('confirmEmailAddressTitle')
    const greeting = t('greeting')
    const enterVerificationCodeText = t('enterVerificationCodeText')
    const verificationCodeExpiryText = t('verificationCodeExpiryText')
    const ignoreEmailText = t('ignoreEmailText')
    const thankYouText = t('thankYouText')

  // Resend verification email
  await sendVerificationEmail(
    user.email,
    user.name,
    newVerificationCode,
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
  const twoFactorCode = user.generateVerificationCode()
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


export {
  verifyEmail,
  resendVerificationEmail,
  send2FACodeBySMS,
}