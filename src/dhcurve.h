#ifndef DHCURVE_H
#define DHCURVE_H

#include <stdio.h>
#include <stdlib.h>

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>

using namespace node;
using namespace v8;

// A helper class that takes care of destroying OpenSSL objects when they go out
// of scope.
template <typename T, void (*destructor)(T*)>
class ScopedOpenSSL {
 public:
  ScopedOpenSSL() : ptr_(NULL) { }
  explicit ScopedOpenSSL(T* ptr) : ptr_(ptr) { }
  ~ScopedOpenSSL() {
    reset(NULL);
  }

  T* get() const { return ptr_; }
  T* release() {
    T* ptr = ptr_;
    ptr_ = NULL;
    return ptr;
  }
  void reset(T* ptr) {
    if (ptr != ptr_) {
      if (ptr_) (*destructor)(ptr_);
      ptr_ = ptr;
    }
  }

 private:
  T* ptr_;
};

typedef ScopedOpenSSL<BIGNUM, BN_clear_free> S_BIGNUM;
typedef ScopedOpenSSL<EC_KEY, EC_KEY_free> S_EC_KEY;
typedef ScopedOpenSSL<EC_POINT, EC_POINT_clear_free> S_EC_POINT;

#define THROW(error) ThrowException(String::New((error)));

#endif