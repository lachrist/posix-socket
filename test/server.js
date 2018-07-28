const PosixSocket = require("../lib/main.js");
const sockfd = PosixSocket.socket(PosixSocket.AF_UNIX, PosixSocket.SOCK_STREAM, 0);
PosixSocket.bind(sockfd, {
  sun_family: PosixSocket.AF_UNIX,
  sun_path: "/tmp/yo.sock"
});
PosixSocket.listen(sockfd, 1);
const address = {};
const sockfd1 = PosixSocket.accept(sockfd, address);
console.log("connection accepted from", address);
const buffer = new ArrayBuffer(100);
const size = PosixSocket.recv(sockfd1, buffer, buffer.byteLength, 0);
console.log("got: <"+String.fromCharCode.apply(null, new Uint16Array(buffer, 0, size))+">");
PosixSocket.close(sockfd);
require("fs").unlinkSync("/tmp/yo.sock");