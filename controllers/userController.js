import User from "../models/UserModel.js"
import TempUser from "../models/TempUserModel.js"
import asyncHandler from "../middleware/asyncHandler.js"
import bcrypt from 'bcrypt'
import generateToken from "../utils/generateToken.js"
import {
  sendVerificationEmail,
  sendForgotPasswordResetLink,
  sendPasswordChangeNotification,
  sendTwoFactorCode
} from "../utils/sendEmail.js"

import registerSchema from "../schemas/registerSchema.js"
import forgotPasswordSchema from "../schemas/forgotPasswordSchema.js"
import resetPasswordSchema from "../schemas/resetPasswordSchema.js"
import changePasswordSchema from "../schemas/changePasswordSchema.js"
import requestIp from 'request-ip'
import resend2FACodeSchema from "../schemas/resend2FACode.js"
import twilioClient from "../utils/twilioClient.js"

const generateAndSaveToken = async user => {
  const verificationToken = user.generateVerificationToken()
  await user.save()
  return verificationToken
}

// Helper function to send verification email to both 
// TempUser or regular User (DRY principle)
const sendVerificationTokenEmail = async (
  email,
  name,
  token,
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
      token,
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
const verifyToken = (user, token, t) => {
  if (!user) throw new Error(t('userNotFound'))
  if (user.verificationToken !== token) throw new Error(t('invalidToken'))
  if (user.verificationExpiry && Date.now() > user.verificationExpiry) throw new Error(t('expiredToken'))
}

// @desc Check if email is in use
// @route POST api/users/check-email-in-use
// @access Public
const checkEmailInUse = asyncHandler(async (req, res) => {

  const { t } = req
  const { email } = req.body

  if (!email) {
    res.status(400)
    throw new Error(t('emailRequired'))
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

  if (!emailRegex.test(email)) {
    res.status(400)
    throw new Error(t('invalidEmailFormat'))
  }

  const emailInUse = await User.findOne({ email })

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
const checkPhoneInUse = asyncHandler(async (req, res) => {
  const { t } = req
  const { phone } = req.body

  if (!phone) {
    res.status(400)
    throw new Error(t('phoneRequired'))
  }

  const phoneInUse = await User.findOne({ phone })

  if (phoneInUse) {
    res.status(400)
    throw new Error(t('phoneInUse'))
  } else {
    res.status(200).json({ message: t('phoneAvailable') })
  }
})

// @desc Register user & get token
// @route POST api/users/
// @access Public
const registerUser = asyncHandler(async (req, res) => {

  const { t } = req
  const { name, surname, gender, dob, email, phone, password, terms } = req.body

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

  const verificationToken = await generateAndSaveToken(tempUser)
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
    await sendVerificationTokenEmail(
      tempUser.email,
      tempUser.name,
      verificationToken,
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

// @desc Login user & get token
// @route POST api/users/login
// @access Public
const loginUser = asyncHandler(async (req, res) => {

  // console.log(req.body.deviceId)
  // console.log(req.body.deviceName)
  // console.log(requestIp.getClientIp(req))

  const { t } = req
  const { email, password, deviceId, deviceName, rememberMe } = req.body

  const user = await User.findOne({ email })

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

    return res.json({
      _id: user._id,
      name: user.name,
      surname: user.surname,
      email: user.email,
      gender: user.gender,
      dob: user.dob,
      phone: user.phone,
      isEmailVerified: true,
      message: 'Login successful!',
      isTwoFactorRequired: false,
    })
  } else {
    res.status(401)
    throw new Error(t('invalidCredentials'))
  }
})

// @desc Verify 2FA code and complete login
// @route POST api/users/verify-2fa
// @access Public
const verifyTwoFactor = asyncHandler(async (req, res) => {

  const { t } = req

  const { email, twoFactorCode, deviceId, deviceName } = req.body
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

    return res.json({
      _id: user._id,
      name: user.name,
      surname: user.surname,
      email: user.email,
      gender: user.gender,
      dob: user.dob,
      phone: user.phone,
      isEmailVerified: true,
      message: t('twoFactorAuthenticationSuccess'),
    })
  } else {
    res.status(401)
    throw new Error(t('invalidTwoFactorCode'))
  }
})

// @desc Resend 2FA code by email
// @route POST api/users/resend-2FA-code-by-email
// @access Public
const resend2FACodeByEmail = asyncHandler(async (req, res) => {

  const { t } = req
  const { email } = req.body

  try {
    // Validate email input
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

  if(user.twoFactorCodeLastSent && user.twoFactorCodeLastSent > oneMinuteAgo){
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
    isTwoFactorRequired : true,
    email: user.email
  })
})


// @desc Resend 2FA code by SMS
// @route POST api/users/resend-2FA-code-by-sms
// @access Public
const resend2FACodeBySMS = asyncHandler(async (req, res) => {
  const { t } = req
  const { phone } = req.body

  // try {
  //   // Validate phone number input
  //   await resend2FACodeSchema.validate(req.body, { abortEarly: false }) 
  // } catch (error) {
  //   res.status(400) 
  //   throw new Error(error.errors ? error.errors.join(', ') : t('validationFailed')) 
  // }

  // Find user by phone number
  const user = await User.findOne({ phone }) 

  if (!user) {
    res.status(404) 
    throw new Error(t('userNotFound')) 
  }

  // Check if a 2FA code was sent within the last minute
  // const oneMinuteAgo = Date.now() - 60 * 1000 

  // if (user.twoFactorCodeLastSent && user.twoFactorCodeLastSent > oneMinuteAgo) {
  //   res.status(429) 
  //   throw new Error(t('verificationCodeCooldown')) 
  // }

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
      to: "+15145762484"
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


// @desc Logout user & clear cookies
// @route POST /api/users/logout
// @access Private
const logoutUser = asyncHandler(async (req, res) => {

  const { t } = req

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

  } catch (error){
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
  checkEmailInUse,
  checkPhoneInUse,
  registerUser,
  verifyEmail,
  resendVerificationEmail,
  loginUser,
  verifyTwoFactor,
  resend2FACodeByEmail,
  resend2FACodeBySMS,
  logoutUser,
  updateUserProfile,
  sendEmailChangeVerification,
  resendEmailChangeVerification,
  verifyEmailChange,
  forgotPassword,
  resetPassword,
  changePassword
}