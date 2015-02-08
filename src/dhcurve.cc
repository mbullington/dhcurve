#include "dhcurve.h"

Handle<Value> bnToBuf(const BIGNUM *bn) {
  int bytes = BN_num_bytes(bn);
  Buffer *buffer = Buffer::New(bytes);

  if(BN_bn2bin(bn, (unsigned char *) Buffer::Data(buffer)) < 0) {
    THROW("Failed to create Buffer from BIGNUM")
    return Undefined();
  }

  return buffer->handle_;
}

BIGNUM *bufToBn(const Handle<Value> buf) {
  BIGNUM *r;
  if((r = BN_bin2bn((unsigned char *) Buffer::Data(buf), Buffer::Length(buf), NULL)) == NULL) {
    THROW("Failed to create BIGNUM from Buffer")
    return NULL;
  }
  return r;
}

EC_POINT *jsPointToPoint(const EC_GROUP *group, const Handle<Object> obj) {
  EC_POINT *point = EC_POINT_new(group);

  if(point == NULL) {
    THROW("Failed to create EC_POINT from Point")
    return NULL;
  }

  S_BIGNUM x(bufToBn(obj->Get(String::New("x"))));

  if(x.get() == NULL) {
    THROW("Failed to create BIGNUM from x")
    return NULL;
  }

  S_BIGNUM y(bufToBn(obj->Get(String::New("y"))));

  if(y.get() == NULL) {
    THROW("Failed to create BIGNUM from y")
    return NULL;
  }

  ScopedOpenSSL<BN_CTX, BN_CTX_free> ctx(BN_CTX_new());
  BN_CTX_start(ctx.get());

  if(EC_POINT_set_affine_coordinates_GF2m(group, point, x.get(), y.get(), ctx.get()) == 0) {
    THROW("Failed to set coords for EC_POINT")
    BN_CTX_end(ctx.get());
    return NULL;
  }

  BN_CTX_end(ctx.get());
  return point;
}

Handle<Value> GetSharedSecret(const Arguments& args) {
  String::Utf8Value namedCurve(args[0]);
  S_EC_KEY key(EC_KEY_new_by_curve_name(OBJ_sn2nid(*namedCurve)));

  if(key.get() == NULL) {
    THROW("Key could not be created using curve name")
    return Undefined();
  }

  Local<Value> buf = args[1];
  S_BIGNUM privateKey(bufToBn(buf));

  if(privateKey.get() == NULL) {
    return Undefined();
  }

  EC_KEY_set_private_key(key.get(), (const BIGNUM *) privateKey.get());

  S_EC_POINT peerKey(jsPointToPoint(EC_KEY_get0_group(key.get()), Local<Object>::Cast(args[2])));

  if(peerKey.get() == NULL) {
    return Undefined();
  }
  
  int length = Buffer::Length(buf);
  char* secret = new char[length];

  if(ECDH_compute_key(secret, length, peerKey.get(), key.get(), NULL) != length) {
    THROW("Can not compute ECDH shared key")
    delete secret;
    return Undefined();
  }

  Buffer *r = Buffer::New(secret, length);
  delete secret;
  return r->handle_;
}

Handle<Value> GenerateKeyPair(const Arguments& args) {
  String::Utf8Value namedCurve(args[0]);
  int curve = OBJ_sn2nid(*namedCurve);

  if(curve == NID_undef) {
    THROW("Invalid curve name")
  }

  S_EC_KEY key(EC_KEY_new_by_curve_name(curve));

  if(key.get() == NULL) {
    THROW("Key could not be created using curve name")
    return Undefined();
  }

  if(EC_KEY_generate_key(key.get()) == 0) {
    THROW("Key failed to generate")
    return Undefined();
  }

  Local<Object> r = Object::New();

  r->Set(String::New("privateKey"), bnToBuf(EC_KEY_get0_private_key(key.get())));

  const EC_POINT *publicKey = EC_KEY_get0_public_key(key.get());
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  S_BIGNUM x(BN_new());
  S_BIGNUM y(BN_new());

  if(publicKey == NULL || group == NULL) {
    THROW("Could not get public key")
    return Undefined();
  }

  EC_POINT_get_affine_coordinates_GFp(group, publicKey, x.get(), y.get(), NULL);

  Local<Object> point = Object::New();

  point->Set(String::New("x"), bnToBuf(x.get()));
  point->Set(String::New("y"), bnToBuf(y.get()));

  r->Set(String::New("publicKey"), point);

  return r;
}

void Init(Handle<Object> exports, Handle<Value> module) {
  NODE_SET_METHOD(exports, "generateKeyPair", GenerateKeyPair);
  NODE_SET_METHOD(exports, "getSharedSecret", GetSharedSecret);
}

NODE_MODULE(dhcurve, Init)
