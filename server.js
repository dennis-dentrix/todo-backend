const dotenv = require("dotenv");
const mongoose = require("mongoose");

dotenv.config({
  path: "./config.env",
});

const app = require("./app");

const port = process.env.port || 8000;
const Database = process.env.DATABASE;

mongoose
  .connect(Database)
  .then((con) =>
    console.log(`MongoDB Database connected with HOST: ${con.connection.host}`)
  );

app.listen(port, () => console.log(`Server started on PORT: ${port}`));
