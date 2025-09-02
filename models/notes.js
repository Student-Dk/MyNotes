const mongoose = require("mongoose");

const notesSchema = new mongoose.Schema(
  {
    userId: { type: String },
    Note_Title: { type: String, required: true },
    Note_content: { type: String, required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Notes", notesSchema);
