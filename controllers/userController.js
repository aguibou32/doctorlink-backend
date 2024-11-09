import User from "../models/UserModel.js"
import TempUser from "../models/TempUserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import bcrypt from 'bcrypt'
import generateToken from "../utils/generateToken.js"

import {
  sendForgotPasswordResetLink,
  sendPasswordChangeNotification,
  sendTwoFactorCode
} from "../utils/sendEmail.js"

import registerSchema from "../schemas/registerSchema.js"
import forgotPasswordSchema from "../schemas/forgotPasswordSchema.js"
import resetPasswordSchema from "../schemas/resetPasswordSchema.js"
import changePasswordSchema from "../schemas/changePasswordSchema.js"
import requestIp from 'request-ip'
import loginSchema from "../schemas/loginSchema.js"


import { sendVerificationEmail } from "../utils/sendEmail.js"

import { 
  generateAndSaveCode, 
} from "./utils/utils.js"


// @desc Get logged in user
// @route GET /api/users
// @access Private
const getUser = asyncHandler(async (req, res) => {
  const { t } = req
  const loggedInUser = req.user

  if (!loggedInUser) {
    return res.status(404).json({ message: t('userNotFound') })
  }
  
  res.status(200).json({ loggedInUser })
})


// @desc Get logged in user
// @route POST /api/users
// @access Public
const registerUser = asyncHandler(async (req, res) => {

  const { t } = req
  const { name, surname, gender, dob, email, phone, password, terms } = req.body

  if (!terms) {
    res.status(400)
    throw new Error('termsAndConditionsError')
  }

  try {
    await registerSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }

  const phoneInUse = await User.findOne({ phone })
  if (phoneInUse) {
    res.status(400)
    throw new Error(t('phoneInUse'))
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

  const verificationCode = await generateAndSaveCode(tempUser)
  // when we call generateAndSaveToken, we are already saving the user, that's why we not saving the user
  // again in the try catch block

  const emailVerificationTitle = t('emailVerificationTitle')
  const confirmEmailAddressTitle = t('confirmEmailAddressTitle')
  const greeting = t('greeting')
  const enterVerificationCodeText = t('enterVerificationCodeText')
  const verificationCodeExpiryText = t('verificationCodeExpiryText')
  const ignoreEmailText = t('ignoreEmailText')
  const thankYouText = t('thankYouText')

  try {
    await sendVerificationEmail(
      tempUser.email,
      tempUser.name,
      verificationCode,
      emailVerificationTitle,
      confirmEmailAddressTitle,
      greeting,
      enterVerificationCodeText,
      verificationCodeExpiryText,
      ignoreEmailText,
      thankYouText
    )

    tempUser.lastVerificationEmailSentAt = Date.now()
    await tempUser.save()

    return res.status(200).json({ email: tempUser.email })

    // res.status(201).json({ email: tempUser.email })
  } catch (error) {
    res.status(500)
    throw new Error(t('cannotSendEmail'))
  }
})

// @desc Login user & get token
// @route POST api/users/login
// @access Public
const loginUser = asyncHandler(async (req, res) => {

  const { t } = req
  const { email, password, deviceId, deviceName, rememberMe } = req.body

  try {
    await loginSchema.validate(req.body, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed'))
  }
  
  const user = await User.findOne({ email: email.toLowerCase() })

  if (user && (await user.matchPassword(password))) {

    const clientIp = requestIp.getClientIp(req)

    const isKnownDevice = user.devices.some(
      (device) =>
        device.deviceId === deviceId &&
        device.deviceName === deviceName &&
        device.clientIp === clientIp
    )

    if (!isKnownDevice) {
      if (user.isTwoFactorEnabled) {

        // Check if last email was sent within the last minute
        const oneMinuteAgo = Date.now() - 60 * 1000
        if (user.twoFactorCodeLastSent && user.twoFactorCodeLastSent > oneMinuteAgo) {
          res.status(429)
          throw new Error(t('verificationCodeCooldown'))
        }

        const twoFactorCode = user.generateTwoFactorCode()
        user.twoFactorCodeLastSent = Date.now()
        await user.save()

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

        // Respond that 2FA is required
        return res.status(200).json({
          isTwoFactorRequired: true,
          email: user.email,
          phone: user.phone,
        })
      }
    }

    user.lastLogin = new Date()
    await user.save()
    generateToken(res, user._id)

    const userInfo = user.toObject()
    delete userInfo._id
    delete userInfo.password
    delete userInfo.devices // If too many devices, it makes the cookie too long and the max for a cookie is 4096 bytes 

    return res.status(200).json({ userInfo })

  } else {
    res.status(401)
    throw new Error(t('invalidCredentials'))
  }
})

// @desc Logout user & clear cookies
// @route POST /api/users/logout
// @access Private
const logoutUser = asyncHandler(async (req, res) => {

  const { t } = req
  // res.clearCookie("jwt", { httpOnly: true, sameSite: "Strict" }) // Same as bellow
  res.cookie('jwt', '', {
    httpOnly: true,
    expires: new Date(0)
  })
  res.status(200).json({ message: t('userLoggedOut') })
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

    const userInfo = updatedUser.toObject()
    delete userInfo._id
    delete userInfo.password
    delete userInfo.devices // If too many devices, it makes the cookie too long and the max for a cookie is 4096 bytes 


    res.status(200).json({
      message: t('userUpdatedSuccessfully'),
      userInfo: userInfo
    })

  } else {
    res.status(404)
    throw new Error(t('userNotFound'))
  }
})


// @desc Forgot password 
// @route POST api/users/forgot-password
// @access Public
const forgotPassword = asyncHandler(async (req, res) => {
  const { t } = req
  const { email } = req.body

  try {
    await forgotPasswordSchema.validate({ email }, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }

  const user = await User.findOne({ email })
  if (!user) {
    res.status(400)
    throw new Error(t('emailNotAssociatedWithAUser'))
  }

  // Check if last email was sent within the last minute
  const oneMinuteAgo = Date.now() - 60 * 1000
  if (user.lastResetPasswordEmailSentAt && user.lastResetPasswordEmailSentAt > oneMinuteAgo) {
    res.status(429)
    throw new Error(t('forgotPasswordCooldown'))
  }


  const resetToken = user.generateResetPasswordToken()
  user.resetPasswordToken = resetToken
  await user.save()

  const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`

  const greeting = t('greeting')
  const resetInstruction = t('resetInstruction')
  const resetPassword = t('resetPassword')
  const copyLinkInstruction = t('copyLinkInstruction')
  const expirationNotice = t('expirationNotice')
  const ignoreInstruction = t('ignoreInstruction')
  const thankYou = t('thankYou')

  try {
    await sendForgotPasswordResetLink(user.email, user.name, resetLink, greeting, resetInstruction, resetPassword, copyLinkInstruction, expirationNotice, ignoreInstruction, thankYou)

    user.lastResetPasswordEmailSentAt = Date.now()
    await user.save()
    res.status(200).json({ message: t('passwordResetEmailSent') })

  } catch (error) {
    res.status(500)
    throw new Error('cannotSendEmail')
  }
})

// @desc Reset password
// @route POST api/users/reset-password
// @access Public
const resetPassword = asyncHandler(async (req, res) => {
  const { t } = req
  const { newPassword, token } = req.body

  try {
    await resetPasswordSchema.validate({ newPassword, token }, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }
  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpiry: { $gt: Date.now() } // Making sure the token hasn't expired
  })


  if (!user) {
    res.status(400)
    throw new Error(t('invalidOrExpiredToken'))
  }

  // Update the user's password

  const salt = await bcrypt.genSalt(10)
  const hashedNewPassword = await bcrypt.hash(newPassword, salt)
  user.password = hashedNewPassword

  // Clear the reset token and expiration time
  user.resetPasswordExpiry = undefined
  user.resetPasswordToken = undefined

  await user.save()
  res.status(200).json({ message: t('passwordResetSuccessful') })
})

// @desc Change password
// @route POST api/users/change-password
// @access Private
const changePassword = asyncHandler(async (req, res) => {
  const { t } = req
  const { currentPassword, newPassword } = req.body

  try {
    await changePasswordSchema.validate({ currentPassword, newPassword }, { abortEarly: false })
  } catch (error) {
    res.status(400)
    throw new Error(error.errors ? error.errors.join(', ') : 'Validation failed')
  }

  const user = await User.findById(req.user.id)

  if (!user) {
    return res.status(404).json({ message: ('userNotFound') })
  }

  const isMatch = await bcrypt.compare(currentPassword, user.password)
  if (!isMatch) {
    return res.status(400).json({ message: t('currentPasswordIncorrect') })
  }

  const salt = await bcrypt.genSalt(10)
  user.password = await bcrypt.hash(newPassword, salt)

  const toEmail = user.email
  const passwordUpdated = t('passwordUpdated')
  const passwordUpdatedTitle = t('passwordUpdatedTitle')
  const greeting = t('greeting')
  const name = user.name
  const passwordUpdatedText = t('passwordUpdatedText')
  const ifNotYouText = t('ifNotYouText')
  const contactSupportText = t('contactSupportText')
  const thankYou = t('thankYou')

  try {
    await sendPasswordChangeNotification(toEmail, passwordUpdated,
      passwordUpdatedTitle, greeting, name, passwordUpdatedText,
      ifNotYouText, contactSupportText, thankYou)

    await user.save()
    res.status(200).json({ message: t('passwordUpdatedSuccessfully') })
  } catch (error) {
    res.status(500)
    throw new Error(t('cannotSendNotificationEmail'))
  }
  res.status(200).json({ message: t('passwordChangedSuccessfully') })
})

export {
  getUser,
  registerUser,
  loginUser,
  logoutUser,
  updateUserProfile,
  forgotPassword,
  resetPassword,
  changePassword
}