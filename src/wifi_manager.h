#pragma once
#include <Arduino.h>
#include <WiFi.h>

class WifiManager {
public:
  void begin();
  int scan();                          // retorna qtd de redes (ou <0 em erro)
  int count() const { return count_; } // redes do ultimo scan
  String ssidAt(int index) const;      // index 1-based, "" se invalido
  int rssiAt(int index) const;
  bool secureAt(int index) const;
  bool connect(const String &ssid, const String &pass, uint32_t timeoutMs = 15000);
  bool connected() const { return WiFi.status() == WL_CONNECTED; }
  String currentSsid() const { return WiFi.SSID(); }
  String ip() const { return WiFi.localIP().toString(); }

private:
  int count_ = 0;
};
