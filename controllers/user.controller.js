const User = require('../models/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

exports.registerUser = async (req, res) => {
    const user = { ...req.body }
    const email = user.email
    const searchRes = await User.findOne({ email })

    if (searchRes) return res.status(402).json({ msg: "Email already exist" })

    try {
        const newUser = await new User({ ...user })
        const salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(newUser.password, salt)

        newUser.password = hash

        await newUser.save()
        res.status(200).json({ msg: "User register successfuly" })
    } catch (error) {
        console.log(error)
        res.status(401).json({ msg: "User register failed" })
    }
}

exports.userLogin = async (req, res) => {
    const { email, password } = req.body

    const FirstUser = await User.findOne({ email })

    if (!FirstUser) return res.status(402).json({ msg: "Email not already exist" })

    const isMatch = await bcrypt.compare(password, FirstUser.password)
    // console.log(isMatch)

    if (!isMatch) return res.status(401).json({ msg: "Bad credentiel" })

    const payload = {
        id: FirstUser._id,
        email: FirstUser.email,
        fullName: FirstUser.fullName,
        phone: FirstUser.phone
    }

    try {
        const token = await jwt.sign(payload, process.env.secretOrKey)
        res.status(200).json({ msg: "Login with sucess", token: `Bearer ${token}` })
    } catch (error) {
        res.status(401).json({ msg: "Login failed" })
    }

}