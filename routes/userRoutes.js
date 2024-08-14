import express from 'express'
const router = express.Router()

import { protect, admin } from '../middleware/authMiddleware.js'
import {
  registerUser,
  sendEmailChangeVerification,
  loginUser,
  updateUserProfile,
  verifyEmail,
  resendVerificationEmail,
  logoutUser
} from '../controllers/userController.js'

import checkObjectId from '../middleware/checkObjectId.js'

router.route('/').post(registerUser)
router.route('/login').post(loginUser)
router.route('/sendEmailChangeVerification').post(protect, sendEmailChangeVerification)
router.route('/update').put(protect, updateUserProfile)
router.route('/verify-email').post(verifyEmail)
router.route('/resend-email-verification').post(resendVerificationEmail)
router.route('/logout').post(protect, logoutUser)

export default router 