import express from 'express'
const router = express.Router()

import { protect } from '../middleware/authMiddleware.js'

import {
  verifyEmail,
  resendVerificationEmail,
  verifyTwoFactor,
  resend2FACodeByEmail,
  send2FACodeBySMS,
  resend2FACodeBySMS,
  sendEmailChangeVerification,
  resendEmailChangeVerification,
  verifyEmailChange,
  verifyPhoneNumber
} from '../controllers/userVerificationController.js'

import checkObjectId from '../middleware/checkObjectId.js'

router.route('/verify-email').post(verifyEmail)
router.route('/resend-email-verification').post(resendVerificationEmail)
router.route('/verify-two-factor').post(verifyTwoFactor)
router.route('/resend-2FA-code-by-email').post(resend2FACodeByEmail)
router.route('/send-2FA-code-by-sms').post(send2FACodeBySMS)
router.route('/resend-2FA-code-by-sms').post(resend2FACodeBySMS)
router.route('/send-email-change-verification').post(protect, sendEmailChangeVerification),
router.route('/resend-email-change-verification').post(protect, resendEmailChangeVerification)
router.route('/verify-new-email').post(protect, verifyEmailChange)
router.route('/verify-phone-number').post(protect, verifyPhoneNumber)

export default router