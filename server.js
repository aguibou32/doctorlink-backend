import dotenv from 'dotenv'
dotenv.config()
import connectDB from "./config/db.js"
import express from 'express'
import cookieParser from 'cookie-parser'
import userRoutes from './routes/userRoutes.js'
import { notFound, errorHandler } from './middleware/errorMiddleware.js'
import cors from 'cors';


// console.log(`Mongo URI: ${process.env.MONGO_URI}`); // Log the URI to debug

connectDB()

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

app.use('/api/users', userRoutes)

app.use(notFound)
app.use(errorHandler)

const port = process.env.PORT || 5000
app.listen(port, () => console.log(`Server Running on port : ${port}`.green.inverse))