import dotenv from 'dotenv'
dotenv.config()
import connectDB from "./config/db.js"
import express from 'express'
import cookieParser from 'cookie-parser'
import userRoutes from './routes/userRoutes.js'
import userVerificationRoutes from './routes/userVerificationRoutes.js'
import { notFound, errorHandler } from './middleware/errorMiddleware.js'
import cors from 'cors';
import i18next from './i18next.js'
import middleware from 'i18next-http-middleware'

// console.log(`Mongo URI: ${process.env.MONGO_URI}`); // Log the URI to debug

connectDB()

const app = express()

app.use(cookieParser()) 
// Aguibou, remember your are using 
// cookies bellow here for translation. So this must come before the other lines
app.use(middleware.handle(i18next))

// We are essentially doing this for each request that is comming 
app.use(async (req, res, next) => {
  // console.log('Cookies:', req.cookies)
  const lng = req.cookies.language || 'fr'
  await i18next.changeLanguage(lng)
  next()
})

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use('/api/users', userRoutes)
app.use('/api/user-verification', userVerificationRoutes)

app.use(notFound)
app.use(errorHandler)

const port = process.env.PORT || 5000
app.listen(port, () => console.log(`Server Running on port : ${port}`.green.inverse))