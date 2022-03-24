require('dotenv').config()
const express = require('express')
const connectDB = require('./config/connectDB')
const user = require('./routes/user')
const passport = require('passport')
const cors = require('cors')

const app = express()

app.use(cors())

// app.use(passport.initialize())


app.use(express.json())

app.use('/user', user)


connectDB()

const PORT = process.env.PORT || process.env.port
app.listen(PORT, err => {
    err ? console.log("Server failed", err)
        : console.log(`Server is running on port ${PORT}`)
})