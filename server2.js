"use strict";

const port = process.env.PORT || 4000;
const app = require("./lib/auth_app");

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
