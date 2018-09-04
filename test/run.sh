
rm /tmp/posix-socket-test
node server.js AF_LOCAL /tmp/posix-socket-test &
sleep 1
node client.js AF_LOCAL /tmp/posix-socket-test

node server.js AF_INET 8080 &
sleep 1
node client.js AF_INET 8080

node server.js AF_INET6 8080 &
sleep 1
node client.js AF_INET6 8080
