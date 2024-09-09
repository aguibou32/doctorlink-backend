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

export const sendVerificationEmail = async (toEmail, name, verificationCode) => {
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

    // Send email
      await transporter.sendMail({
      from: `DocLink <noreply@doclink.com>`,
      to: toEmail,
      subject: 'Please Verify Your Email Address',
      html: htmlTemplate,
    })

    // console.log('Email sent: %s', info.messageId)
  } catch (error) {
    console.error('Error sending email:', error)
    throw new Error('Failed to send verification email')
  }
}



export const sendForgotPasswordResetLink = async (toEmail, name, resetLink, greeting, resetInstruction, resetPassword ,copyLinkInstruction, expirationNotice, ignoreInstruction, thankYou) => {
  try {
    
    const templatePath = path.join(__dirname, 'forgotPassword', 'forgotPassword.html')

    // Check if the file exists
    if (!fs.existsSync(templatePath)) {
      console.error('Template file does not exist at path:', templatePath)
      throw new Error('Template file does not exist')
    }

    // Read the HTML template
    let htmlTemplate = fs.readFileSync(templatePath, 'utf-8')

    // Replace the placeholder with the actual verification code
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

    // console.log('Email sent: %s', info.messageId)
  } catch (error) {
    console.error('Error sending email:', error)
    throw new Error('Failed to send verification email')
  }
}