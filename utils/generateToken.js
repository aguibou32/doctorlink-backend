import jwt from 'jsonwebtoken';

const generateToken = (res, userId) => {
  // Create a JWT token
  const token = jwt.sign({ userId: userId }, process.env.JWT_SECRET, {
    expiresIn: '30d'
  });

  // Set JWT as HTTP-Only cookie
  res.cookie('jwt', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Use secure cookies only in production
    sameSite: 'strict', // Helps prevent cross-site request forgery
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds
  });
};

export default generateToken;
