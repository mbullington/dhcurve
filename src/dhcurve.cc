#include <node.h>
#include <v8.h>

using namespace v8;

#define EXPORT(exports, name, function) (exports)->Set(String::NewSymbol("(name)"), FunctionTemplate::New((function))->GetFunction())

Handle<Value> GenerateKeyPair(const Arguments& args) {
}

void Init(Handle<Object> exports) {
  EXPORT(exports, generateKeyPair, GenerateKeyPair)
}

NODE_MODULE(dhcurve, init)
