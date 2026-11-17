#include "ble_transport.h"

#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

static const size_t BLE_CHUNK = 20;  // seguro com o MTU padrao (23 - 3)

void BleTransport::begin() {
  NimBLEDevice::init("MyESP32");
  NimBLEServer *server = NimBLEDevice::createServer();
  NimBLEService *service = server->createService(SERVICE_UUID);
  chr_ = service->createCharacteristic(
      CHARACTERISTIC_UUID,
      NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::NOTIFY);
  chr_->setCallbacks(this);
  service->start();

  NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(SERVICE_UUID);
  adv->start();
}

void BleTransport::onWrite(NimBLECharacteristic *c, NimBLEConnInfo &) {
  std::string v = c->getValue();
  std::lock_guard<std::mutex> lock(mtx_);
  rx_.concat(v.c_str(), v.length());
}

bool BleTransport::poll(String &out) {
  std::lock_guard<std::mutex> lock(mtx_);
  int nl = rx_.indexOf('\n');
  if (nl < 0) return false;
  out = rx_.substring(0, nl);
  rx_.remove(0, nl + 1);
  out.trim();
  return out.length() > 0;
}

void BleTransport::send(const String &msg) {
  String data = msg + "\n";
  for (size_t i = 0; i < data.length(); i += BLE_CHUNK) {
    String part = data.substring(i, i + BLE_CHUNK);
    chr_->setValue((const uint8_t *)part.c_str(), part.length());
    chr_->notify();
    delay(10);
  }
}
