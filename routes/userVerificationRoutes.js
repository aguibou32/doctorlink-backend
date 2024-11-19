import express from 'express'
const router = express.Router()

import { protect } from '../middleware/authMiddleware.js'

import {
  verifyUser,
  resendVerificationCodeByEmail,
  sendVerificationCodeBySMS
} from '../controllers/userVerificationController.js'

import checkObjectId from '../middleware/checkObjectId.js'

router.route('/verify-user').post(verifyUser)
router.route('/resend-verification').post(resendVerificationCodeByEmail)
router.route('/send-verification-code-by-sms').post(sendVerificationCodeBySMS)

export default router