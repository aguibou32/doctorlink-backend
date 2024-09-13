import express from 'express'
const router = express.Router()

import { protect, admin } from '../middleware/authMiddleware.js'
import {
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
  verifyEmailChange,
  forgotPassword,
  resetPassword,
  changePassword

} from '../controllers/userController.js'

import checkObjectId from '../middleware/checkObjectId.js'

router.route('/').post(registerUser)
router.route('/check-email-in-use').post(checkEmailInUse)
router.route('/check-phone-in-use').post(checkPhoneInUse)
router.route('/verify-email').post(verifyEmail)
router.route('/resend-email-verification').post(resendVerificationEmail)
router.route('/login').post(loginUser)
router.route('/logout').post(protect, logoutUser)
router.route('/update').put(protect, updateUserProfile)
router.route('/send-email-change-verification').post(protect, sendEmailChangeVerification),
router.route('/resend-email-change-verification').post(protect, resendEmailChangeVerification)
router.route('/verify-new-email').post(protect, verifyEmailChange)
router.route('/forgot-password').post(forgotPassword)
router.route('/reset-password').post(resetPassword)
router.route('/change-password').post(protect, changePassword)

export default router 