#include "dhcurve.h"

Local<Value> bnToBuf(const BIGNUM *bn) {
  int bytes = BN_num_bytes(bn);
  Local<Object> buffer = NanNewBufferHandle(bytes);

  if(BN_bn2bin(bn, (unsigned char *) Buffer::Data(buffer)) < 0) {
    NanThrowError("Failed to create Buffer from BIGNUM");
    return NanUndefined();
  }

  return buffer;
}

BIGNUM *bufToBn(const Local<Value> buf) {
  BIGNUM *r;
  if((r = BN_bin2bn((unsigned char *) Buffer::Data(buf), Buffer::Length(buf), NULL)) == NULL) {
    NanThrowError("Failed to create BIGNUM from Buffer");
    return NULL;
  }
  return r;
}

EC_POINT *jsPointToPoint(const EC_GROUP *group, const Local<Object> obj) {
  EC_POINT *point = EC_POINT_new(group);

  if(point == NULL) {
    NanThrowError("Failed to create EC_POINT from Point");
    return NULL;
  }

  S_BIGNUM x(bufToBn(obj->Get(NanNew<String>("x"))));

  if(x.get() == NULL) {
    NanThrowError("Failed to create BIGNUM from x");
    return NULL;
  }

  S_BIGNUM y(bufToBn(obj->Get(NanNew<String>("y"))));

  if(y.get() == NULL) {
    NanThrowError("Failed to create BIGNUM from y");
    return NULL;
  }

  ScopedOpenSSL<BN_CTX, BN_CTX_free> ctx(BN_CTX_new());
  BN_CTX_start(ctx.get());

  if(EC_POINT_set_affine_coordinates_GF2m(group, point, x.get(), y.get(), ctx.get()) == 0) {
    NanThrowError("Failed to set coords for EC_POINT");
    BN_CTX_end(ctx.get());
    return NULL;
  }

  BN_CTX_end(ctx.get());
  return point;
}

NAN_METHOD(GetSharedSecret) {
  NanScope();

  NanUtf8String namedCurve(args[0]);
  S_EC_KEY key(EC_KEY_new_by_curve_name(OBJ_sn2nid(*namedCurve)));

  if(key.get() == NULL) {
    NanThrowError("Key could not be created using curve name");
    NanReturnUndefined();
  }

  Local<Value> buf = args[1];
  S_BIGNUM privateKey(bufToBn(buf));

  if(privateKey.get() == NULL) {
    NanThrowError("Could not use private key");
    NanReturnUndefined();
  }

  EC_KEY_set_private_key(key.get(), (const BIGNUM *) privateKey.get());

  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  S_EC_POINT peerKey(jsPointToPoint(group, Local<Object>::Cast(args[2])));

  if(peerKey.get() == NULL) {
    NanThrowError("Could not use remote public key provided");
    NanReturnUndefined();
  }

  int length = Buffer::Length(buf);

  if((EC_GROUP_get_degree(group) + 7) / 8 != length) {
    NanThrowError("Private key is incorrect size");
    NanReturnUndefined();
  }

  char* secret = new char[length];

  if(ECDH_compute_key(secret, length, peerKey.get(), key.get(), NULL) != length) {
    NanThrowError("Can not compute ECDH shared key");
    delete secret;
    NanReturnUndefined();
  }

  Local<Object> r = NanNewBufferHandle(secret, length);
  delete secret;
  NanReturnValue(r);
}

NAN_METHOD(GenerateKeyPair) {
  NanScope();

  NanUtf8String namedCurve(args[0]);
  int curve = OBJ_sn2nid(*namedCurve);

  if(curve == NID_undef) {
    NanThrowError("Invalid curve name");
  }

  S_EC_KEY key(EC_KEY_new_by_curve_name(curve));

  if(key.get() == NULL) {
    NanThrowError("Key could not be created using curve name");
    NanReturnUndefined();
  }

  if(EC_KEY_generate_key(key.get()) == 0) {
    NanThrowError("Key failed to generate");
    NanReturnUndefined();
  }

  Local<Object> r = NanNew<Object>();

  r->Set(NanNew<String>("privateKey"), bnToBuf(EC_KEY_get0_private_key(key.get())));

  const EC_POINT *publicKey = EC_KEY_get0_public_key(key.get());
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  S_BIGNUM x(BN_new());
  S_BIGNUM y(BN_new());

  if(publicKey == NULL || group == NULL) {
    NanThrowError("Could not get public key");
    NanReturnUndefined();
  }

  EC_POINT_get_affine_coordinates_GFp(group, publicKey, x.get(), y.get(), NULL);

  Local<Object> point = NanNew<Object>();

  point->Set(NanNew<String>("x"), bnToBuf(x.get()));
  point->Set(NanNew<String>("y"), bnToBuf(y.get()));

  r->Set(NanNew<String>("publicKey"), point);

  NanReturnValue(r);
}

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "generateKeyPair", GenerateKeyPair);
  NODE_SET_METHOD(exports, "getSharedSecret", GetSharedSecret);
}

NODE_MODULE(dhcurve, init)
