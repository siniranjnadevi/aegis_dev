// sample_config.js - Target Configuration File
const apiKey = "AKIA_IOSFODNN7EXAMPLE";
const dbPassword = "super_secret_password_123";

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};
