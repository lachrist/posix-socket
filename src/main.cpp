
// http://man7.org/linux/man-pages/man7/unix.7.html
// struct sockaddr_un {
//    sa_family_t sun_family;               /* AF_UNIX */
//    char        sun_path[108];            /* pathname */
// };

// https://linux.die.net/man/7/ip
// struct sockaddr_in {
//     sa_family_t    sin_family; /* address family: AF_INET */
//     in_port_t      sin_port;   /* port in network byte order */
//     struct in_addr sin_addr;   /* internet address */
// };
// struct in_addr {
//     uint32_t       s_addr;     /* address in network byte order */
// };

// http://man7.org/linux/man-pages/man7/ipv6.7.html
// struct sockaddr_in6 {
//    sa_family_t     sin6_family;   /* AF_INET6 */
//    in_port_t       sin6_port;     /* port number */
//    uint32_t        sin6_flowinfo; /* IPv6 flow information */
//    struct in6_addr sin6_addr;     /* IPv6 address */
//    uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
// };
// struct in6_addr {
//    unsigned char   s6_addr[16];   /* IPv6 address */
// };

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <node.h>

static size_t max_length;

void ThrowErrno (v8::Isolate* isolate) {
  char string[100];
  snprintf(string, 100, "ERRNO %i: %s", errno, std::strerror(errno));
  isolate->ThrowException(v8::String::NewFromUtf8(isolate, string));
}

void ThrowMessage (v8::Isolate* isolate, const char* message) {
  isolate->ThrowException(v8::String::NewFromUtf8(isolate, message));
}

int ThrowErrnoInt (v8::Isolate* isolate, int result) {
  ThrowErrno(isolate);
  return result;
}

int ThrowMessageInt (v8::Isolate* isolate, const char* message, int result) {
  ThrowMessage(isolate, message);
  return result;
}

// Convert a JavaScript value to a sockaddr
int ObjectToAddress(v8::Object* object, sockaddr* address) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Context> context = isolate->GetEnteredContext();
  if (object->Has(v8::String::NewFromUtf8(isolate, "sun_family"))) {
    v8::Local<v8::Value> sun_family = object->Get(context, v8::String::NewFromUtf8(isolate, "sun_family")).ToLocalChecked();
    v8::Local<v8::Value> sun_path = object->Get(context, v8::String::NewFromUtf8(isolate, "sun_path")).ToLocalChecked();
    if (!sun_family->IsNumber())
      return ThrowMessageInt(isolate, "addr.sun_family must be a Number", -1);
    if (!sun_path->IsString())
      return ThrowMessageInt(isolate, "addr.sun_path must be a String", -1);
    ((struct sockaddr_un *) address)->sun_family = sun_family->Uint32Value();
    strncpy(((struct sockaddr_un *) address)->sun_path, *v8::String::Utf8Value(isolate, sun_path), sizeof(((sockaddr_un*)0)->sun_path));
    return sizeof(sockaddr_un);
  }
  if (object->Has(v8::String::NewFromUtf8(isolate, "sin_family"))) {
    v8::Local<v8::Value> sin_family = object->Get(context, v8::String::NewFromUtf8(isolate, "sin_family")).ToLocalChecked();
    v8::Local<v8::Value> sin_port = object->Get(context, v8::String::NewFromUtf8(isolate, "sin_port")).ToLocalChecked();
    v8::Local<v8::Value> sin_addr = object->Get(context, v8::String::NewFromUtf8(isolate, "sin_addr")).ToLocalChecked();
    if (!sin_family->IsNumber())
      return ThrowMessageInt(isolate, "addr.sin_family must be a Number", -1);
    if (!sin_port->IsNumber())
      return ThrowMessageInt(isolate, "addr.sin_port must be a Number", -1);
    if (!sin_addr->IsString())
      return ThrowMessageInt(isolate, "addr.sin_addr must be a String", -1);
    ((struct sockaddr_in *) address)->sin_family = sin_family->Uint32Value();
    ((struct sockaddr_in *) address)->sin_port = htonl(sin_port->Uint32Value());
    if (inet_pton(AF_INET, *v8::String::Utf8Value(isolate, sin_addr), &(((struct sockaddr_in *) address)->sin_addr)) == 0)
      return ThrowMessageInt(isolate, "addr.sin_addr could not be parsed", -1);
    return sizeof(sockaddr_in);
  }
  if (object->Has(v8::String::NewFromUtf8(isolate, "sin6_family"))) {
    v8::Local<v8::Value> sin6_family = object->Get(context, v8::String::NewFromUtf8(isolate, "sin6_family")).ToLocalChecked();
    v8::Local<v8::Value> sin6_port = object->Get(context, v8::String::NewFromUtf8(isolate, "sin6_port")).ToLocalChecked();
    v8::Local<v8::Value> sin6_flowinfo = object->Get(context, v8::String::NewFromUtf8(isolate, "sin6_flowinfo")).ToLocalChecked();
    v8::Local<v8::Value> sin6_addr = object->Get(context, v8::String::NewFromUtf8(isolate, "sin6_addr")).ToLocalChecked();
    v8::Local<v8::Value> sin6_scope_id = object->Get(context, v8::String::NewFromUtf8(isolate, "sin6_scope_id")).ToLocalChecked();
    if (!sin6_family->IsNumber())
      return ThrowMessageInt(isolate, "addr.sin6_family must be a Number", -1);
    if (!sin6_port->IsNumber())
      return ThrowMessageInt(isolate, "addr.sin6_port must be a Number", -1);
    if (!sin6_flowinfo->IsNumber())
      return ThrowMessageInt(isolate, "addr.sin6_flowinfo must be a Number", -1);
    if (!sin6_flowinfo->IsString())
      return ThrowMessageInt(isolate, "addr.sin6_addr must be a String", -1);
    if (!sin6_scope_id->IsNumber())
      return ThrowMessageInt(isolate, "addr.sin6_scope_id field must be a Number", -1);
    ((struct sockaddr_in6 *) address)->sin6_family = sin6_family->Uint32Value();
    ((struct sockaddr_in6 *) address)->sin6_port = htonl(sin6_port->Uint32Value());
    ((struct sockaddr_in6 *) address)->sin6_flowinfo = sin6_flowinfo->Uint32Value();
    if (inet_pton(AF_INET, *v8::String::Utf8Value(isolate, sin6_addr), &(((struct sockaddr_in6 *) address)->sin6_addr)) == 0)
      return ThrowMessageInt(isolate, "addr.sin_addr could not be parsed", -1);
    ((struct sockaddr_in6 *) address)->sin6_scope_id = sin6_scope_id->Uint32Value();
  }
  return ThrowMessageInt(isolate, "addr must contain either sun_family, sin_family, or sin6_family", -1);
};

void AddressToObject (sockaddr* address, v8::Object* object) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Context> context = isolate->GetEnteredContext();
  if (address->sa_family == AF_UNIX || address->sa_family == AF_LOCAL) {
    sa_family_t sun_family = ((struct sockaddr_un*) address)->sun_family;
    char* sun_path = ((struct sockaddr_un*) address)->sun_path;
    object->Set(context, v8::String::NewFromUtf8(isolate, "sun_family"), v8::Number::New(isolate, sun_family)).FromJust();
    object->Set(context, v8::String::NewFromUtf8(isolate, "sun_path"), v8::String::NewFromUtf8(isolate, sun_path)).FromJust();
  } else if (address->sa_family == AF_INET) {
    sa_family_t sin_family = ((struct sockaddr_in*) address)->sin_family;
    in_port_t sin_port = ntohl(((struct sockaddr_in*) address)->sin_port);
    char sin_addr[20];
    if (inet_ntop(AF_INET, &((struct sockaddr_in*) address)->sin_addr, sin_addr, 20) == NULL) {
      ThrowErrno(isolate);
    } else {
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin_family"), v8::Number::New(isolate, sin_family)).FromJust();
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin_port"), v8::Number::New(isolate, sin_port)).FromJust();
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin_addr"), v8::String::NewFromUtf8(isolate, sin_addr)).FromJust();
    }
  } else if (address->sa_family == AF_INET6) {
    sa_family_t sin6_family = ((struct sockaddr_in6*) address)->sin6_family;
    in_port_t sin6_port = ntohl(((struct sockaddr_in6*) address)->sin6_port);
    uint32_t sin6_flowinfo = ((struct sockaddr_in6*) address)->sin6_flowinfo;
    char sin6_addr[50];
    if (inet_ntop(AF_INET6, &((struct sockaddr_in6*) address)->sin6_addr, sin6_addr, 50) == NULL) {
      ThrowErrno(isolate);
    } else {
      uint32_t sin6_scope_id = ((struct sockaddr_in6*) address)->sin6_scope_id;
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin6_family"), v8::Number::New(isolate, sin6_family)).FromJust();
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin6_port"), v8::Number::New(isolate, sin6_port)).FromJust();
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin6_flowinfo"), v8::Number::New(isolate, sin6_flowinfo)).FromJust();
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin6_addr"), v8::String::NewFromUtf8(isolate, sin6_addr)).FromJust();
      object->Set(context, v8::String::NewFromUtf8(isolate, "sin6_scope_id"), v8::Number::New(isolate, sin6_scope_id)).FromJust();
    }
  } else {
    ThrowMessage(isolate, "only the following address families are supported: AF_UNIX, AF_LOCAL, AF_INET and, AF_INET6");
  }
}

// http://man7.org/linux/man-pages/man2/socket.2.html
// int socket(int domain, int type, int protocol);
void Socket(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (info.Length() != 3)
    return ThrowMessage(isolate, "socket(domain, type, protocol) expects 3 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "domain must be a Number");
  if (!info[1]->IsNumber())
    return ThrowMessage(isolate, "type must be a Number");
  if (!info[2]->IsNumber())
    return ThrowMessage(isolate, "protocol must be a Number");
  int socketfd = socket(info[0]->Int32Value(), info[1]->Int32Value(), info[2]->Int32Value());
  if (socketfd == -1) {
    ThrowErrno(isolate);
  } else {
    info.GetReturnValue().Set(v8::Integer::New(isolate, socketfd));
  }
}

// http://man7.org/linux/man-pages/man2/connect.2.html
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
void Connect (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (info.Length() != 2)
    return ThrowMessage(isolate, "connect(sockfd, addr) expects 2 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsObject())
    return ThrowMessage(isolate, "addr must be an Object");
  sockaddr* address = (sockaddr*) malloc(max_length);
  int length = ObjectToAddress(v8::Object::Cast(*info[1]), address);
  if (length != -1) {
    if (connect(info[0]->Int32Value(), address, length) == -1) {
      ThrowErrno(isolate);
    }
  }
  free(address);
};

// http://man7.org/linux/man-pages/man2/bind.2.html
// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
void Bind (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (info.Length() != 2)
    return ThrowMessage(isolate, "connect(sockfd, addr) expects 2 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  sockaddr* address = (sockaddr*) malloc(max_length);
  int length = ObjectToAddress(v8::Object::Cast(*info[1]), address);
  if (length != -1) {
    if (bind(info[0]->Int32Value(), address, length) == -1) {
      ThrowErrno(isolate);
    }
  }
  free(address);
};

// http://man7.org/linux/man-pages/man2/listen.2.html
// int listen(int sockfd, int backlog);
void Listen (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (info.Length() != 2)
    return ThrowMessage(isolate, "listen(sockfd, backlog) expects 2 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsNumber())
    return ThrowMessage(isolate, "backlog must be a Number");
  if (listen(info[0]->Int32Value(), info[0]->Int32Value()) == -1) {
    ThrowErrno(isolate);
  }
}

// http://man7.org/linux/man-pages/man2/accept.2.html
// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
void Accept (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 2)
    return ThrowMessage(isolate, "accept(sockfd, addr) expects 2 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsObject())
    return ThrowMessage(isolate, "addr must be an Object");
  sockaddr* address = (sockaddr*) malloc(max_length);
  socklen_t actual_length = max_length;
  int sockfd = accept(info[0]->Int32Value(), address, &actual_length);
  if (sockfd == -1) {
    ThrowErrno(isolate);
  } else {
    AddressToObject(address, v8::Object::Cast(*info[1]));
    info.GetReturnValue().Set(v8::Integer::New(isolate, sockfd));
  }
  free(address);
}

// http://man7.org/linux/man-pages/man2/send.2.html
// ssize_t send(int sockfd, void *buf, size_t len, int flags);
void Send (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 4)
    return ThrowMessage(isolate, "send(sockfd, buf, len, flags) expects 4 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsArrayBuffer())
    return ThrowMessage(isolate, "buf must be an ArrayBuffer");
  if (!info[2]->IsNumber())
    return ThrowMessage(isolate, "len must be a number");
  if (!info[3]->IsNumber())
    return ThrowMessage(isolate, "flags must be a Number");
  ssize_t size = send(info[0]->Int32Value(), v8::ArrayBuffer::Cast(*(info[1]))->GetContents().Data(), info[2]->Int32Value(), info[3]->Int32Value());
  if (size == -1) {
    ThrowErrno(isolate);
  } else {
    info.GetReturnValue().Set(v8::Integer::New(isolate, size));
  }
};

// http://man7.org/linux/man-pages/man2/send.2.html
// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
void Sendto (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 5)
    return ThrowMessage(isolate, "sendto(sockfd, buf, len, flags, dest_addr) expects 5 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsArrayBuffer())
    return ThrowMessage(isolate, "buf must be an ArrayBuffer");
  if (!info[2]->IsNumber())
    return ThrowMessage(isolate, "len must be a number");
  if (!info[3]->IsNumber())
    return ThrowMessage(isolate, "flags must be a number");
  if (!info[4]->IsObject())
    return ThrowMessage(isolate, "dest_addr must be an object");
  sockaddr* address = (sockaddr*) malloc(max_length);
  int length = ObjectToAddress(v8::Object::Cast(*info[4]), address);
  if (length != -1) {
    ssize_t size = sendto(info[0]->Int32Value(), v8::ArrayBuffer::Cast(*(info[1]))->GetContents().Data(), info[2]->Int32Value(), info[3]->Int32Value(), address, length);
    if (size == -1) {
      ThrowErrno(isolate);
    } else {
      AddressToObject(address, v8::Object::Cast(*info[3]));
      info.GetReturnValue().Set(v8::Integer::New(isolate, size));
    }
  }
  free(address);
}

// http://man7.org/linux/man-pages/man2/recv.2.html
// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
void Recv (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 4)
    return ThrowMessage(isolate, "recv(sockfd, buf, len flags) expects 4 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsArrayBuffer())
    return ThrowMessage(isolate, "buf must be an ArrayBuffer");
  if (!info[2]->IsNumber())
    return ThrowMessage(isolate, "len must be a number");
  if (!info[3]->IsNumber())
    return ThrowMessage(isolate, "flags must be a Number");
  ssize_t size = recv(info[0]->Int32Value(), v8::ArrayBuffer::Cast(*(info[1]))->GetContents().Data(), info[2]->Int32Value(), info[3]->Int32Value());
  if (size == -1) {
    ThrowErrno(isolate);
  } else {
    info.GetReturnValue().Set(v8::Integer::New(isolate, size));
  }
};

// http://man7.org/linux/man-pages/man2/recv.2.html
// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
void Recvfrom (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 5)
    return ThrowMessage(isolate, "recvfrom(sockfd, buf, len, flags, src_addr) expects 4 arguments");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsArrayBuffer())
    return ThrowMessage(isolate, "buf must be an ArrayBuffer");
  if (!info[2]->IsNumber())
    return ThrowMessage(isolate, "len must be a number");
  if (!info[3]->IsNumber())
    return ThrowMessage(isolate, "flags must be a number");
  if (!info[4]->IsObject())
    return ThrowMessage(isolate, "src_addr must be an object");
  sockaddr* address = (sockaddr*) malloc(max_length);
  socklen_t actual_length = max_length;
  ssize_t size = recvfrom(info[0]->Int32Value(), v8::ArrayBuffer::Cast(*(info[1]))->GetContents().Data(), info[2]->Int32Value(), info[3]->Int32Value(), address, &actual_length);
  if (size == -1) {
    ThrowErrno(isolate);
  } else {
    AddressToObject(address, v8::Object::Cast(*info[3]));
    info.GetReturnValue().Set(v8::Integer::New(isolate, size));
  }
  free(address);
}

// http://man7.org/linux/man-pages/man2/close.2.html
// int close(int fd);
void Close (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 1)
    return ThrowMessage(isolate, "close(fd) expects 1 argument");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "fd must be a Number");
  if (close(info[0]->Int32Value()) == -1) {
    ThrowErrno(isolate);
  }
}

// http://man7.org/linux/man-pages/man2/shutdown.2.html
// int shutdown(int sockfd, int how);
void Shutdown (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 2)
    return ThrowMessage(isolate, "shutdown(sockfd, how) expects 2 argument");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsNumber())
    return ThrowMessage(isolate, "how must be a Number");
  if (shutdown(info[0]->Int32Value(), info[1]->Int32Value()) == -1) {
    ThrowErrno(isolate);
  }
}

// http://man7.org/linux/man-pages/man2/getsockopt.2.html
// int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
void Getsockopt (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 1)
    return ThrowMessage(isolate, "getsockopt(sockfd, level, optname) expects 3 argument");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsNumber())
    return ThrowMessage(isolate, "level must be a Number");
  if (!info[2]->IsNumber())
    return ThrowMessage(isolate, "optname must be a Number");
  int optval;
  socklen_t optlen = sizeof(int);
  if (getsockopt(info[0]->Int32Value(), info[1]->Int32Value(), info[2]->Int32Value(), (void *) &optval, &optlen) == -1) {
    ThrowErrno(isolate);
  } else {
    info.GetReturnValue().Set(v8::Integer::New(isolate, optval));
  }
}

// http://man7.org/linux/man-pages/man2/setsockopt.2.html
// int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
void Setsockopt (const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (info.Length() != 1)
    return ThrowMessage(isolate, "getsockopt(sockfd, level, optname, optval) expects 3 argument");
  if (!info[0]->IsNumber())
    return ThrowMessage(isolate, "sockfd must be a Number");
  if (!info[1]->IsNumber())
    return ThrowMessage(isolate, "level must be a Number");
  if (!info[2]->IsNumber())
    return ThrowMessage(isolate, "optname must be a Number");
  if (!info[3]->IsNumber())
    return ThrowMessage(isolate, "optval must be a Number");
  int optval = info[0]->Int32Value();
  socklen_t optlen = sizeof(int);
  if (setsockopt(info[0]->Int32Value(), info[1]->Int32Value(), info[2]->Int32Value(), (void *) &optval, optlen) == -1) {
    ThrowErrno(isolate);
  }
}

void Initialize(v8::Local<v8::Object> exports) {

  max_length = sizeof(sockaddr_un);
  max_length = sizeof(sockaddr_in)  > max_length ? sizeof(sockaddr_in)  : max_length;
  max_length = sizeof(sockaddr_in6) > max_length ? sizeof(sockaddr_in6) : max_length;

  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Context> context = isolate->GetEnteredContext();

  exports->Set(context, v8::String::NewFromUtf8(isolate, "AF_LOCAL"), v8::Integer::New(isolate, AF_LOCAL)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "AF_UNIX"), v8::Integer::New(isolate, AF_UNIX)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "AF_INET"), v8::Integer::New(isolate, AF_INET)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "AF_INET6"), v8::Integer::New(isolate, AF_INET6)).FromJust();

  exports->Set(context, v8::String::NewFromUtf8(isolate, "SOCK_STREAM"), v8::Integer::New(isolate, SOCK_STREAM)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "SOCK_DGRAM"), v8::Integer::New(isolate, SOCK_DGRAM)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "SOCK_SEQPACKET"), v8::Integer::New(isolate, SOCK_SEQPACKET)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "SOCK_RAW"), v8::Integer::New(isolate, SOCK_RAW)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "SOCK_RDM"), v8::Integer::New(isolate, SOCK_RDM)).FromJust();

  exports->Set(context, v8::String::NewFromUtf8(isolate, "MSG_DONTWAIT"), v8::Integer::New(isolate, MSG_DONTWAIT)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "MSG_OOB"), v8::Integer::New(isolate, MSG_OOB)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "MSG_PEEK"), v8::Integer::New(isolate, MSG_PEEK)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "MSG_TRUNC"), v8::Integer::New(isolate, MSG_TRUNC)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "MSG_WAITALL"), v8::Integer::New(isolate, MSG_WAITALL)).FromJust();

  exports->Set(context, v8::String::NewFromUtf8(isolate, "SHUT_WR"), v8::Integer::New(isolate, SHUT_WR)).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "SHUT_RDWR"), v8::Integer::New(isolate, SHUT_RDWR)).FromJust();

  exports->Set(context, v8::String::NewFromUtf8(isolate, "socket"), v8::FunctionTemplate::New(isolate, Socket)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "bind"), v8::FunctionTemplate::New(isolate, Bind)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "connect"), v8::FunctionTemplate::New(isolate, Connect)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "listen"), v8::FunctionTemplate::New(isolate, Listen)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "accept"), v8::FunctionTemplate::New(isolate, Accept)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "send"), v8::FunctionTemplate::New(isolate, Send)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "sendto"), v8::FunctionTemplate::New(isolate, Sendto)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "recv"), v8::FunctionTemplate::New(isolate, Recv)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "recvfrom"), v8::FunctionTemplate::New(isolate, Recvfrom)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "close"), v8::FunctionTemplate::New(isolate, Close)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "shutdown"), v8::FunctionTemplate::New(isolate, Shutdown)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "getsockopt"), v8::FunctionTemplate::New(isolate, Getsockopt)->GetFunction()).FromJust();
  exports->Set(context, v8::String::NewFromUtf8(isolate, "setsockopt"), v8::FunctionTemplate::New(isolate, Setsockopt)->GetFunction()).FromJust();

}

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
