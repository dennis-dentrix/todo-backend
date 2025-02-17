// task/listModel.js
const mongoose = require("mongoose");

const listSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, "A list must have a title"],
  },
  category: {
    type: String,
    required: [true, "A list must have a category"],
  },
  description: {
    type: String,
    required: [true, "A list must have a description"],
  },
  createdAt: {
    type: Date,
    default: Date.now, // Changed to Date.now to store the current timestamp
  },
  dueDate: { 
    type: Date, 
    default: Date.now 
  },
  remark: {
    type: String,
  },
  status: {
    type: String,
    enum: ["incomplete", "completed"],
    default: "incomplete",
  },
  user: { // ADD THIS FIELD
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'List must belong to a user']
  }
});

listSchema.pre("save", async function (next) {
  console.log(listSchema.user)
  if (this.isNew) {
    const existingList = await mongoose.models.List.findOne({
      title: this.title,
    });

    if (existingList) {
      // console.log("Document Exists");

      const err = new Error("A list with this title already exists.");
      return next(err);
    }
  } else {
    console.log("Document updated");
  }
  next();
});
const List = mongoose.model("List", listSchema);

module.exports = List;

