
const PosixSocket = require("../lib/main.js");

exports["AF_LOCAL"] = (path) => ({
  sun_family: PosixSocket.AF_LOCAL,
  sun_path: path
});

exports["AF_INET"] = (port) => ({
  sin_family: PosixSocket.AF_INET,
  sin_port: parseInt(port),
  sin_addr: "127.0.0.1"
});

exports["AF_INET6"] = (port) => ({
  sin6_family: PosixSocket.AF_INET6,
  sin6_port: 8080,
  sin6_flowinfo: 0,
  sin6_addr: "::1",
  sin6_scope_id: 0
});
