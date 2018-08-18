const PosixSocket = require("../lib/main.js");
const Addresses = require("./addresses.js");
const sockfd = PosixSocket.socket(PosixSocket[process.argv[2]], PosixSocket.SOCK_STREAM, 0);
PosixSocket.connect(sockfd, Addresses[process.argv[2]](process.argv[3]));
const buffer = new ArrayBuffer(100);
const view = new Uint16Array(buffer, 0, buffer.length);
const string = "HelloWorld!";
for (let i = 0; i<string.length; i++)
  view[i] = string.charCodeAt(i);
PosixSocket.send(sockfd, buffer, string.length*view.BYTES_PER_ELEMENT, 0);
PosixSocket.close(sockfd);