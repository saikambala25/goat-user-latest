const serverless = require("serverless-http");
const app = require("./api/app");

exports.main_handler = serverless(app);
