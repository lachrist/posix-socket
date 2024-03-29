console.log(`node version = ${process.version}`);
const PosixSocket = require("../lib/main.js");
const Addresses = require("./addresses.js");
const sockfd = PosixSocket.socket(PosixSocket[process.argv[2]], PosixSocket.SOCK_STREAM, 0);
PosixSocket.bind(sockfd, Addresses[process.argv[2]](process.argv[3]));
PosixSocket.listen(sockfd, 1);
const address = {};
const sockfd1 = PosixSocket.accept(sockfd, address);
console.log("connection accepted from", address);
const buffer = new ArrayBuffer(100);
const size = PosixSocket.recv(sockfd1, buffer, buffer.byteLength, 0);
console.log("got: <"+String.fromCharCode.apply(null, new Uint16Array(buffer, 0, size))+">");
PosixSocket.close(sockfd);