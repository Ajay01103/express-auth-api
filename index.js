const express = require("express")
const Datastore = require("nedb-promises")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const config = require("./config")

const app = express()
const port = 3000 || process.env.PORT

app.use(express.json())

const users = Datastore.create("Users.db")

app.get("/", (req, res) => {
  res.send("Rest API Authentication and Authorization")
})

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body

    if (!name || !email || !password) {
      return res.status(422).json({ message: "Please fill all the required fields" })
    }

    const existingUser = await users.findOne({
      email,
    })

    if (existingUser) {
      return res.status(409).json({ message: "Email already exist" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = await users.insert({
      name,
      email,
      password: hashedPassword,
    })

    return res.status(201).json({ message: "User registered successfully", id: newUser._id })
  } catch (error) {
    return res.status(500).json({ message: error.message })
  }
})

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(422).json({ message: "Please fill all the required fields" })
    }

    const user = await users.findOne({
      email,
    })

    if (!user) {
      return res.status(401).json({ message: "Email or password is invalid" })
    }

    const passwordMatch = await bcrypt.compare(password, user.password)

    if (!passwordMatch) {
      return res.status(401).json({ message: "Email or password is invalid" })
    }

    const accessToken = jwt.sign({ userId: user._id }, config.accessTokenSecret, {
      subject: "accessAPI",
      expiresIn: "2h",
    })

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
    })
  } catch (error) {
    return res.status(500).json({ message: error.message })
  }
})

app.get("/api/users/current", ensureAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({
      _id: req.user.id,
    })

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
    })
  } catch (error) {
    return res.status(500).json({ message: error.message })
  }
})

async function ensureAuthenticated(req, res, next) {
  const accessToken = req.headers.authorization

  if (!accessToken) {
    return res.status(401).json({ message: "Access Token not found" })
  }

  try {
    const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret)

    req.user = { id: decodedAccessToken.userId }

    next()
  } catch (error) {
    return res.status(401).json({ message: "Access Token is invalid or expired" })
  }
}

app.listen(port, () => console.log(`Server started on port ${port}`))
