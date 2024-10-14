import express from 'express'
const router = express.Router()

import { protect } from '../middleware/authMiddleware.js'
import {
  checkEmailInUse,
  checkPhoneInUse,
  getUser,
  registerUser,
  loginUser,
  logoutUser,
  updateUserProfile,

  forgotPassword,
  resetPassword,
  changePassword
} from '../controllers/userController.js'

import checkObjectId from '../middleware/checkObjectId.js'

router.route('/get-user').get(protect, getUser)
router.route('/').post(registerUser)
router.route('/check-email-in-use').post(checkEmailInUse)
router.route('/check-phone-in-use').post(checkPhoneInUse)
router.route('/login').post(loginUser)
router.route('/logout').post(protect, logoutUser)
router.route('/update').put(protect, updateUserProfile)
router.route('/forgot-password').post(forgotPassword)
router.route('/reset-password').post(resetPassword)
router.route('/change-password').post(protect, changePassword)

export default router 