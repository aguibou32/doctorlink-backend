import dotenv from 'dotenv'
dotenv.config()
import connectDB from "./config/db.js"
import express from 'express'
import userRoutes from './routes/userRoutes.js'


// console.log(`Mongo URI: ${process.env.MONGO_URI}`); // Log the URI to debug

connectDB()

const app = express()
const port = process.env.PORT || 5000
app.listen(port, () => console.log(`Server Running on port: ${port}`.green.inverse))
