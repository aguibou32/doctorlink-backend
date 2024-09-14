import dotenv from 'dotenv'
dotenv.config()
import nodemailer from 'nodemailer'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { dirname } from 'path'

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT, 10),
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
})

export const sendVerificationEmail = async (
  toEmail,
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

    const templatePath = path.join(__dirname, 'emailVerification', 'emailVerification.html')
    // console.log(`Template path: ${templatePath}`)

    // Check if the file exists
    if (!fs.existsSync(templatePath)) {
      console.error('Template file does not exist at path:', templatePath)
      throw new Error('Template file does not exist')
    }

    // Read the HTML template
    let htmlTemplate = fs.readFileSync(templatePath, 'utf-8')

    // Replace the placeholder with the actual verification code
    htmlTemplate = htmlTemplate.replace('{{verificationCode}}', verificationCode)
      .replace('{{name}}', name)
      .replace('{{emailVerificationTitle}}', emailVerificationTitle)
      .replace('{{confirmEmailAddressTitle}}', confirmEmailAddressTitle)
      .replace('{{greeting}}', greeting)
      .replace('{{enterVerificationCodeText}}', enterVerificationCodeText)
      .replace('{{verificationCodeExpiryText}}', verificationCodeExpiryText)
      .replace('{{ignoreEmailText}}', ignoreEmailText)
      .replace('{{thankYouText}}', thankYouText)

    // Send email
    await transporter.sendMail({
      from: `DocLink <noreply@doclink.com>`,
      to: toEmail,
      subject: 'Please Verify Your Email Address',
      html: htmlTemplate,
    })

  } catch (error) {
    console.error('Error sending email:', error)
    throw new Error('Failed to send verification email')
  }
}



export const sendForgotPasswordResetLink = async (toEmail, name, resetLink, greeting, resetInstruction, resetPassword, copyLinkInstruction, expirationNotice, ignoreInstruction, thankYou) => {

  try {
    const templatePath = path.join(__dirname, 'forgotPassword', 'forgotPassword.html')

    // Check if the file exists
    if (!fs.existsSync(templatePath)) {
      console.error('Template file does not exist at path:', templatePath)
      throw new Error('Template file does not exist')
    }

    // Read the HTML template
    let htmlTemplate = fs.readFileSync(templatePath, 'utf-8')

    htmlTemplate = htmlTemplate.replace('{{resetLink}}', resetLink)
      .replace('{{greeting}}', greeting)
      .replace('{{resetPassword}}', resetPassword)
      .replace('{{resetInstruction}}', resetInstruction)
      .replace('{{resetInstruction}}', resetInstruction)
      .replace('{{copyLinkInstruction}}', copyLinkInstruction)
      .replace('{{expirationNotice}}', expirationNotice)
      .replace('{{ignoreInstruction}}', ignoreInstruction)
      .replace('{{thankYou}}', thankYou)
      .replace('{{name}}', name)

    // Send email
    await transporter.sendMail({
      from: `DocLink <noreply@doclink.com>`,
      to: toEmail,
      subject: 'Password reset link',
      html: htmlTemplate,
    })

  } catch (error) {
    console.error('Error sending email:', error)
    throw new Error('Failed to reset password email')
  }
}

export const sendPasswordChangeNotification = async (
  toEmail,
  passwordUpdated, passwordUpdatedTitle, greeting, name, passwordUpdatedText,
  ifNotYouText, contactSupportText, thankYou
) => {

  try {
    const templatePath = path.join(__dirname, 'passwordChange', 'passwordChange.html')

    // Check if the file exists
    if (!fs.existsSync(templatePath)) {
      console.error('Template file does not exist at path:', templatePath)
      throw new Error('Template file does not exist')
    }

    // Read the HTML template
    let htmlTemplate = fs.readFileSync(templatePath, 'utf-8')

    htmlTemplate = htmlTemplate.replace('{{passwordUpdated}}', passwordUpdated)
      .replace('{{passwordUpdatedTitle}}', passwordUpdatedTitle)
      .replace('{{greeting}}', greeting)
      .replace('{{name}}', name)
      .replace('{{passwordUpdatedText}}', passwordUpdatedText)
      .replace('{{ifNotYouText}}', ifNotYouText)
      .replace('{{contactSupportText}}', contactSupportText)
      .replace('{{thankYou}}', thankYou)

    // Send email
    await transporter.sendMail({
      from: `DocLink <notify@doclink.com>`,
      to: toEmail,
      subject: 'Password Update Notification',
      html: htmlTemplate,
    })
  } catch (error) {
    console.error('Error sending email:', error)
    throw new Error('Failed to send password change notification email')
  }
}

export const sendTwoFactorCode = async (
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
) => {

  try {
    const templatePath = path.join(__dirname, 'twoFactor', 'twoFactor.html')

    // Check if the file exists
    if (!fs.existsSync(templatePath)) {
      console.error('Template file does not exist at path:', templatePath)
      throw new Error('Template file does not exist')
    }

    // Read the HTML template
    let htmlTemplate = fs.readFileSync(templatePath, 'utf-8')

    htmlTemplate = htmlTemplate.replace('{{twoFactorAuthentication}}', twoFactorAuthentication)
      .replace('{{twoFactorAuthenticationTitle}}', twoFactorAuthenticationTitle)
      .replace('{{greeting}}', greeting)
      .replace('{{twoFactorAuthenticationText}}', twoFactorAuthenticationText)
      .replace('{{name}}', name)
      .replace('{{twoFactorCode}}', twoFactorCode)
      .replace('{{authenticationCode}}', authenticationCode)
      .replace('{{ifNotYouText}}', ifNotYouText)
      .replace('{{contactSupportText}}', contactSupportText)
      .replace('{{thankYou}}', thankYou)

    // Send email
    await transporter.sendMail({
      from: `DocLink <notify@doclink.com>`,
      to: toEmail,
      subject: '2 Factor Authentication Notification',
      html: htmlTemplate,
    })

  } catch (error) {
    console.error('Error sending email:', error)
    throw new Error('Failed to send 2 factor authentication email')
  }

}