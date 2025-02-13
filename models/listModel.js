const mongoose = require("mongoose");

const listSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, "A list must have a title"],
    unique: true,
  },
  description: {
    type: String,
    required: [true, "A list must have a description"],
  },
  createdAt: {
    type: Date,
    default: Date.now, // Fix default value
  },
  remark: {
    type: String,
  },
  status: {
    type: String,
    enum: ["pending", "completed"],
    default: "pending",
  },
});

listSchema.pre("save", async function (next) {
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
