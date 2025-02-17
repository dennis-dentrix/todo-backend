const List = require('../models/listModel');

exports.createItem = async (req, res) => {
  try {
    const newItem = await List.create({
      ...req.body,
      user: req.user._id
    });

    res.status(201).json({
      status: "success",
      data: {
        item: newItem
      }
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    });
  }
};

exports.getAllItems = async (req, res) => {
  try {
    const list = await List.find({ user: req.user._id });

    res.status(200).json({
      status: "success",
      results: list.length,
      data: {
        list
      }
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    });
  }
};

exports.getAnItem = async (req, res) => {
  try {
    const item = await List.findOne({ _id: req.params.id, user: req.user._id });

    if (!item) {
      return res.status(404).json({
        status: "fail",
        message: "No item found with that ID"
      });
    }

    res.status(200).json({
      status: "success",
      data: {
        item
      }
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    });
  }
};

exports.updateItem = async (req, res) => {
  try {
    const item = await List.findOneAndUpdate(
      { _id: req.params.id, user: req.user._id },
      req.body,
      {
        new: true,
        runValidators: true
      }
    );

    if (!item) {
      return res.status(404).json({
        status: "fail",
        message: "No item found with that ID"
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        item
      }
    });
  } catch (error) {
    res.status(404).json({
      status: "fail",
      message: error
    });
  }
};

exports.deleteItem = async (req, res) => {
  try {
    const item = await List.findOneAndDelete({ _id: req.params.id, user: req.user._id });

    if (!item) {
      return res.status(404).json({
        status: "fail",
        message: "No item found with that ID"
      });
    }

    res.status(204).json({
      status: "success",
      data: null
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    });
  }
};