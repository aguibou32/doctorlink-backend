import express from 'express'
const router = express.Router()

import {protect, admin} from '../middleware/authMiddleware.js'
import { registerUser, loginUser, verifyEmail, resendVerificationEmail, logoutUser } from '../controllers/userController.js'

router.route('/').post(registerUser)
router.route('/login').post(loginUser)
router.post('/verify-email', verifyEmail)
router.post('/resend-email-verification', resendVerificationEmail)
router.route('/logout', protect).post(logoutUser)

export default router 