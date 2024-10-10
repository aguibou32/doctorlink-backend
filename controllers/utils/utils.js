import { 
  sendVerificationEmail,
  sendForgotPasswordResetLink,
  sendPasswordChangeNotification,
  sendTwoFactorCode
 } from "../../utils/sendEmail.js"


 // Helper function to use User or Temp model function generateVerificationToken() 
 // to generate and save token to database
export const generateAndSaveToken = async user => {
  const verificationToken = user.generateVerificationToken()
  await user.save()
  return verificationToken
}

// Helper function to send verification email to both 
// TempUser or regular User (DRY principle)
export const sendVerificationTokenEmail = async (
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
export const verifyToken = (user, token, t) => {
  if (!user) throw new Error(t('userNotFound'))
  if (user.verificationToken !== token) throw new Error(t('invalidToken'))
  if (user.verificationExpiry && Date.now() > user.verificationExpiry) throw new Error(t('expiredToken'))
}