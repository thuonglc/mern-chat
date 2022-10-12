const { StatusCodes } = require("http-status-codes");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const { BadRequestError } = require("../errors/bad-request");
const User = require("../models/user.model");

var that = (module.exports = {
  register: async (req, res, next) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ message: "Please provide all values" });
    }
    if (!validator.isEmail(email)) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ message: "Invalid Email" });
    }

    const isUserExists = await User.findOne({ email: email });
    if (isUserExists) {
      res
        .status(StatusCodes.BAD_REQUEST)
        .json({ message: "User with this Email Already Exists" });
    }

    //hashing password
    const hashPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      email,
      password: hashPassword,
    });

    if (user) {
      const token = jwt.sign(
        {
          userId: user._id,
          username: user.username,
          userEmail: user.email,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.JWT_LIFETIME,
        }
      );

      res.status(StatusCodes.CREATED).json({
        _id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
        token,
      });
    }
  },
  login: async (req, res) => {
    const { username, email, password } = req.body;

    if (!email || !password) {
      res
        .status(StatusCodes.BAD_REQUEST)
        .json({ message: "Please Provide All the Values" });
    }

    const isUser = await User.findOne({
      $or: [{ email: email }, { username: username }],
    });

    if (!isUser) {
      res
        .status(StatusCodes.BAD_REQUEST)
        .json({ message: "Invalid Credentials" });
    } else {
      //compare password
      const comparePassword = await bcrypt.compare(password, isUser.password);

      if (!comparePassword) {
        res.status(StatusCodes.BAD_REQUEST).json({
          message: "Please Make Sure You have entered Correct Password!",
        });
      }

      const token = jwt.sign(
        {
          userId: isUser._id,
          username: isUser.username,
          userEmail: isUser.email,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.JWT_LIFETIME,
        }
      );

      res.status(StatusCodes.OK).json({
        _id: isUser._id,
        username: isUser.username,
        email: isUser.email,
        avatar: isUser.avatar,
        token,
      });
    }
  },
  searchUser: async (req, res) => {
    const { search } = req.query;

    if (!search) {
      res.status(StatusCodes.OK).json([]);
    } else {
      const user = await User.find({
        username: { $regex: search, $options: "i" },
        _id: { $ne: req.user.id },
      }).select("username avatar _id email bio");

      res.status(StatusCodes.OK).json(user);
    }
  },
});
