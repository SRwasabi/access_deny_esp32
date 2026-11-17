#include "wifi_manager.h"

void WifiManager::begin() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
}

int WifiManager::scan() {
  int n = WiFi.scanNetworks();
  count_ = n > 0 ? n : 0;
  return n;
}

static bool validIndex(int index, int count) { return index >= 1 && index <= count; }

String WifiManager::ssidAt(int index) const {
  return validIndex(index, count_) ? WiFi.SSID(index - 1) : String("");
}

int WifiManager::rssiAt(int index) const {
  return validIndex(index, count_) ? WiFi.RSSI(index - 1) : 0;
}

bool WifiManager::secureAt(int index) const {
  return validIndex(index, count_) && WiFi.encryptionType(index - 1) != WIFI_AUTH_OPEN;
}

bool WifiManager::connect(const String &ssid, const String &pass, uint32_t timeoutMs) {
  WiFi.disconnect();
  WiFi.begin(ssid.c_str(), pass.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(250);
  }
  return connected();
}
