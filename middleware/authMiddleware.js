import jwt from 'jsonwebtoken'
import asyncHandler from './asyncHandler.js'
import User from '../models/UserModel.js'


// Protect Routes
const protect = asyncHandler(async (req, res, next) => {
  let token

  token = req.cookies.jwt

  if(token){
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET)
      req.user = await User.findById(decoded.userId).select('-password')
      next()
    } catch (error) {
      res.status(401)
      throw new Error('Not Authorized, token failed')
    }
  }else{
    res.status(401)
    throw new Error('Not authorized, no token')
  }
})

// Only admin access
const admin = (req, res, next) => {
  if(req.user && req.user.role === 'admin'){
    next()
  }else{
    res.status(401)
    throw new Error('Not authorized as admin')
  }
}

export {protect, admin}