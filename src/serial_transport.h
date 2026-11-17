#pragma once
#include "transport.h"

class SerialTransport : public Transport {
public:
  void begin() override;
  bool poll(String &out) override;
  void send(const String &msg) override;

private:
  String buf_;
};
