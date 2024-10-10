import express from 'express'
const router = express.Router()

import { protect } from '../middleware/authMiddleware.js'

import {
  verifyEmail,
  resendVerificationEmail,
  verifyTwoFactor,
  resend2FACodeByEmail,
  resend2FACodeBySMS
} from '../controllers/userVerificationController.js'

import checkObjectId from '../middleware/checkObjectId.js'

router.route('/verify-email').post(verifyEmail)
router.route('/resend-email-verification').post(resendVerificationEmail)
router.route('/verify-two-factor').post(verifyTwoFactor)
router.route('/resend-2FA-code-by-email').post(resend2FACodeByEmail)
router.route('/resend-2FA-code-by-sms').post(resend2FACodeBySMS)

export default router