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

#define THROW(error) ThrowException(String::New((error)));

// referenced bignumToBuffer() from ursa, in src/ursaNative.cc L91
// Copyright 2012 The Obvious Corporation.
Handle<Value> bnToBuf(const BIGNUM *bn) {
  int bytes = BN_num_bytes(bn);
  Buffer *buffer = Buffer::New(bytes);
  
  if(BN_bn2bin(bn, (unsigned char *) Buffer::Data(buffer)) < 0) {
    delete buffer;
    THROW("Failed to create Buffer from BIGNUM.")
    return Undefined();
  }
  
  return buffer->handle_;
}

Handle<Value> GetSharedSecret(const Arguments& args) {
  return Undefined();
}

Handle<Value> GenerateKeyPair(const Arguments& args) {
  String::Utf8Value namedCurve(args[0]);
  EC_KEY *key;
  int curve = OBJ_sn2nid(*namedCurve);
  
  if(curve == NID_undef) {
    THROW("Invalid curve name")
  }
  
  if((key = EC_KEY_new_by_curve_name(curve)) == NULL) {
    THROW("Key could not be created using curve name")
    EC_KEY_free(key);
    return Undefined();
  }
  
  if(EC_KEY_generate_key(key) == 0) {
    THROW("Key failed to generate")
    EC_KEY_free(key);
    return Undefined();
  }
  
  Local<Object> returnValue = Object::New();
  
  returnValue->Set(String::New("privateKey"), bnToBuf(EC_KEY_get0_private_key(key)));
  
  const EC_POINT *publicKey = EC_KEY_get0_public_key(key);
  const EC_GROUP *group = EC_KEY_get0_group(key);
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  
  if(publicKey == NULL || group == NULL) {
    BN_clear_free(x);
    BN_clear_free(y);
    EC_KEY_free(key);
    THROW("Could not get public key")
    return Undefined();
  }
  
  EC_POINT_get_affine_coordinates_GFp(group, publicKey, x, y, NULL);
  
  Local<Object> point = Object::New();
  
  point->Set(String::New("x"), bnToBuf(x));
  point->Set(String::New("y"), bnToBuf(y));
  
  returnValue->Set(String::New("publicKey"), point);
  
  BN_clear_free(x);
  BN_clear_free(y);
  EC_KEY_free(key);
  
  return returnValue;
}

void Init(Handle<Object> exports, Handle<Value> module) {
  NODE_SET_METHOD(exports, "generateKeyPair", GenerateKeyPair);
  NODE_SET_METHOD(exports, "getSharedSecret", GetSharedSecret);
}

NODE_MODULE(dhcurve, Init)