#include "dhcurve.h"

Local<Value> bnToBuf(const BIGNUM *bn) {
  int bytes = BN_num_bytes(bn);
  Local<Object> buffer = Nan::NewBuffer(bytes).ToLocalChecked();

  if(BN_bn2bin(bn, (unsigned char *) Buffer::Data(buffer)) <= 0) {
    THROW("Failed to create Buffer from BIGNUM");
    return Nan::Undefined();
  }

  return buffer;
}

BIGNUM *bufToBn(const Local<Value> buf) {
  BIGNUM *r;
  if((r = BN_bin2bn((unsigned char *) Buffer::Data(buf), Buffer::Length(buf), NULL)) == NULL) {
    THROW("Failed to create BIGNUM from Buffer");
    return NULL;
  }
  return r;
}

EC_POINT *jsPointToPoint(const EC_GROUP *group, const Local<Object> obj) {
  EC_POINT *point = EC_POINT_new(group);

  if(point == NULL) {
    THROW("Failed to create EC_POINT from Point");
    return NULL;
  }

  S_BIGNUM x(bufToBn(Nan::Get(obj, Nan::New<String>("x").ToLocalChecked()).ToLocalChecked()));

  if(x.get() == NULL) {
    THROW("Failed to create BIGNUM from x");
    return NULL;
  }

  S_BIGNUM y(bufToBn(Nan::Get(obj, Nan::New<String>("y").ToLocalChecked()).ToLocalChecked()));

  if(y.get() == NULL) {
    THROW("Failed to create BIGNUM from y");
    return NULL;
  }

  ScopedOpenSSL<BN_CTX, BN_CTX_free> ctx(BN_CTX_new());
  BN_CTX_start(ctx.get());

  if(EC_POINT_set_affine_coordinates_GF2m(group, point, x.get(), y.get(), ctx.get()) <= 0) {
    THROW("Failed to set coords for EC_POINT");
    BN_CTX_end(ctx.get());
    return NULL;
  }

  BN_CTX_end(ctx.get());
  return point;
}

void GenerateKeyPair(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  Nan::Utf8String namedCurve(info[0]);
  int curve = OBJ_sn2nid(*namedCurve);

  if(curve == NID_undef) {
    THROW("Invalid curve name");
    return;
  }

  S_EC_KEY key(EC_KEY_new_by_curve_name(curve));

  if(key.get() == NULL) {
    THROW("Key could not be created using curve name");
    return;
  }

  if(EC_KEY_generate_key(key.get()) <= 0) {
    THROW("Key failed to generate");
    return;
  }

  Local<Object> r = Nan::New<Object>();

  Nan::Set(r, Nan::New<String>("privateKey").ToLocalChecked(), bnToBuf(EC_KEY_get0_private_key(key.get())));

  const EC_POINT *publicKey = EC_KEY_get0_public_key(key.get());
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  S_BIGNUM x(BN_new());
  S_BIGNUM y(BN_new());

  if(publicKey == NULL || group == NULL) {
    THROW("Could not get public key");
    return;
  }

  EC_POINT_get_affine_coordinates_GFp(group, publicKey, x.get(), y.get(), NULL);

  Local<Object> point = Nan::New<Object>();

  Nan::Set(point, Nan::New<String>("x").ToLocalChecked(), bnToBuf(x.get()));
  Nan::Set(point, Nan::New<String>("y").ToLocalChecked(), bnToBuf(y.get()));

  Nan::Set(r, Nan::New<String>("publicKey").ToLocalChecked(), point);

  info.GetReturnValue().Set(r);
}

void GetSharedSecret(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  Nan::Utf8String namedCurve(info[0]);
  S_EC_KEY key(EC_KEY_new_by_curve_name(OBJ_sn2nid(*namedCurve)));

  if(key.get() == NULL) {
    THROW("Key could not be created using curve name");
    return;
  }

  Local<Value> buf = info[1];
  S_BIGNUM privateKey(bufToBn(buf));

  if(privateKey.get() == NULL) {
    THROW("Could not use private key");
    return;
  }

  EC_KEY_set_private_key(key.get(), (const BIGNUM *) privateKey.get());

  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  S_EC_POINT peerKey(jsPointToPoint(group, info[2].As<Object>()));

  if(peerKey.get() == NULL) {
    THROW("Could not use remote public key provided");
    return;
  }

  int length = Buffer::Length(buf);

  if((EC_GROUP_get_degree(group) + 7) / 8 != length) {
    THROW("Private key is incorrect size");
    return;
  }

  char* secret = new char[length];

  if(ECDH_compute_key(secret, length, peerKey.get(), key.get(), NULL) != length) {
    THROW("Can not compute ECDH shared key");
    delete secret;
    return;
  }

  Local<Object> r = Nan::NewBuffer(secret, length).ToLocalChecked();
  info.GetReturnValue().Set(r);
}

void GetPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  Nan::Utf8String namedCurve(info[0]);
  S_EC_KEY key(EC_KEY_new_by_curve_name(OBJ_sn2nid(*namedCurve)));

  if(key.get() == NULL) {
    THROW("Key could not be created using curve name");
    return;;
  }

  Local<Value> buf = info[1];
  S_BIGNUM privateKey(bufToBn(buf));

  if(privateKey.get() == NULL) {
    THROW("Could not use private key");
    return;;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  S_EC_POINT publicKey(EC_POINT_new(group));

  if(group == NULL) {
    THROW("Could not get EC_GROUP");
    return;;
  }

  if(publicKey.get() == NULL) {
    THROW("Could not get EC_POINT");
    return;;
  }

  ScopedOpenSSL<BN_CTX, BN_CTX_free> ctx(BN_CTX_new());
  BN_CTX_start(ctx.get());

  if(EC_POINT_mul(group, publicKey.get(), privateKey.get(), NULL, NULL, ctx.get()) <= 0) {
    THROW("Failed to multiply private key");
    BN_CTX_end(ctx.get());
    return;;
  }

  S_BIGNUM x(BN_new());
  S_BIGNUM y(BN_new());

  EC_POINT_get_affine_coordinates_GFp(group, publicKey.get(), x.get(), y.get(), ctx.get());

  BN_CTX_end(ctx.get());

  Local<Object> point = Nan::New<Object>();

  Nan::Set(point, Nan::New<String>("x").ToLocalChecked(), bnToBuf(x.get()));
  Nan::Set(point, Nan::New<String>("y").ToLocalChecked(), bnToBuf(y.get()));

  info.GetReturnValue().Set(point);
}

void init(Handle<Object> exports) {
  Nan::SetMethod(exports, "generateKeyPair", GenerateKeyPair);
  Nan::SetMethod(exports, "getSharedSecret", GetSharedSecret);
  Nan::SetMethod(exports, "getPublicKey", GetPublicKey);
}

NODE_MODULE(dhcurve, init)
