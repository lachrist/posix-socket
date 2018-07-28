const PosixSocket = require("../lib/main.js");
const sockfd = PosixSocket.socket(PosixSocket.AF_UNIX, PosixSocket.SOCK_STREAM, 0);
PosixSocket.connect(sockfd, {
  sun_family: PosixSocket.AF_UNIX,
  sun_path: "/tmp/yo.sock"
});
const buffer = new ArrayBuffer(100);
const view = new Uint16Array(buffer, 0, buffer.length);
const string = "HelloWorld!";
for (let i = 0; i<string.length; i++)
  view[i] = string.charCodeAt(i);
PosixSocket.send(sockfd, buffer, string.length*view.BYTES_PER_ELEMENT, 0);