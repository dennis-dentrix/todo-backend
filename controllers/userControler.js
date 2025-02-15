const User = require("../models/userModel");

exports.getAllUsers = async (req, res, next) => {
  try {
    const user = await User.find();
    res.status(200).json({
      status: "success",
      data: { user },
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      messade: error,
    });
  }
};
