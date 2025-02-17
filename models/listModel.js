// task/listModel.js
const mongoose = require("mongoose");
const AppError = require("../utils/appError");

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
    default: Date.now,
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

// listSchema.pre("save", async function (next) {
//   if (this.isNew) {
//     const existingList = await mongoose.models.List.findOne({
//       title: this.title,
//       user: this.user
//     });
//     console.log(existingList);

//     if (existingList) {
//       return next(new AppError("A list with this title already exists.", 400));
//     }
//   } else {
//     console.log("Document updated");
//   }
//   next();
// });
const List = mongoose.model("List", listSchema);

module.exports = List;

