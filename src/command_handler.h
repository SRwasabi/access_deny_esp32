#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>
#include "wifi_manager.h"

// Interpreta um comando JSON e devolve a resposta JSON.
// Nao sabe de onde o comando veio (Serial, BLE, ...).
//
// Comandos:
//   {"cmd":"scan"}
//   {"cmd":"connect","index":2,"pass":"senha"}      (index do ultimo scan, 1-based)
//   {"cmd":"connect","ssid":"MinhaRede","pass":"senha"}
//   {"cmd":"status"}
class CommandHandler {
public:
  explicit CommandHandler(WifiManager &wifi) : wifi_(wifi) {}
  String handle(const String &line);

private:
  String doScan();
  String doConnect(JsonVariantConst req);
  String doStatus();
  WifiManager &wifi_;
};
