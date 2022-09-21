"use strict";

const port = process.env.PORT || 3000;
const app = require("./lib/app");

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
