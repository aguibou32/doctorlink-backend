import express from 'express'
const router = express.Router()

import { protect } from '../middleware/authMiddleware.js'

import {
  verifyEmail,
  resendVerificationEmail,
} from '../controllers/userVerificationController.js'

import checkObjectId from '../middleware/checkObjectId.js'

router.route('/verify-email').post(verifyEmail)
router.route('/resend-verification-email').post(resendVerificationEmail)


export default router