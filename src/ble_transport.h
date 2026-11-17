#pragma once
#include <NimBLEDevice.h>
#include <mutex>
#include "transport.h"

// Recebe comandos por escrita na characteristic (remonta fragmentos ate o '\n')
// e responde por notify, quebrando a resposta em pedacos.
class BleTransport : public Transport, public NimBLECharacteristicCallbacks {
public:
  void begin() override;
  bool poll(String &out) override;
  void send(const String &msg) override;

  // NimBLE-Arduino 2.x
  void onWrite(NimBLECharacteristic *c, NimBLEConnInfo &connInfo) override;

private:
  NimBLECharacteristic *chr_ = nullptr;
  String rx_;
  std::mutex mtx_;
};
