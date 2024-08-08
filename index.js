const express = require("express")
const Datastore = require("nedb-promises")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const config = require("./config")

const app = express()
const port = 3000 || process.env.PORT

app.use(express.json())

const users = Datastore.create("Users.db")
const userRefreshToken = Datastore.create("UserRefreshToken.db")

app.get("/", (req, res) => {
  res.send("Rest API Authentication and Authorization")
})

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body

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
      role: role ?? "member",
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

    const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, {
      subject: "refreshToken",
      expiresIn: "1w",
    })

    await userRefreshToken.insert({
      refreshToken,
      userId: user._id,
    })

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
      refreshToken,
    })
  } catch (error) {
    return res.status(500).json({ message: error.message })
  }
})

app.post("/api/auth/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh Token not found" })
    }

    const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret)

    const userRefreshToken = await userRefreshToken.findOne({
      refreshToken,
      userId: decodedRefreshToken.userId,
    })

    if (!userRefreshToken) {
      return res.status(401).json({ message: "Rferesh TOken invalid or expired" })
    }

    await userRefreshToken.remove({
      _id: userRefreshToken._id,
    })

    await userRefreshToken.compactDatafile()

    const accessToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.accessTokenSecret, {
      subject: "accessAPI",
      expiresIn: "2h",
    })

    const newrefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.refreshTokenSecret,
      {
        subject: "refreshToken",
        expiresIn: "1w",
      }
    )

    await userRefreshToken.insert({
      newrefreshToken,
      userId: decodedRefreshToken.userId,
    })

    return res.status(200).json({
      accessToken,
      refreshToken: newrefreshToken,
    })
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ message: "Rferesh TOken invalid or expired" })
    }

    return res.status(500).json({ message: error.message })
  }
})

app.get("/api/auth/logout", ensureAuthenticated, async (req, res) => {
  try {
    await userRefreshTokens.removeMany({ userId: req.user.id })
    await userRefreshTokens.compactDatafile()

    await userInvalidTokens.insert({
      accessToken: req.accessToken.value,
      userId: req.user.id,
      expirationTime: req.accessToken.exp,
    })

    return res.status(204).send()
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

app.get("/api/admin", ensureAuthenticated, authorize(["admin"]), (req, res) => {
  return res.status(200).json({ message: "Only admins can access this route" })
})

app.get("/api/moderator", ensureAuthenticated, authorize(["admin", "moderator"]), (req, res) => {
  return res.status(200).json({ message: "Only admins and moderators can access this route" })
})

function authorize(roles = []) {
  return async function (req, res, next) {
    const user = await users.findOne({
      _id: req.user.id,
    })

    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Access denied" })
    }

    next()
  }
}

app.listen(port, () => console.log(`Server started on port ${port}`))
