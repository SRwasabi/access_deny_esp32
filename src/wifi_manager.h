#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <vector>
#include "packet_sniffer.h"

enum class WifiState { IDLE, SCANNING, CONNECTING, CONNECTED, LOCKED, SNIFFING };

class WifiManager {
public:
  void begin();

  // Scan ativo. Guarda tambem BSSID e canal de cada rede.
  int scan();                          // retorna qtd de redes (ou <0 em erro)
  int count() const { return count_; } // redes do ultimo scan
  String ssidAt(int index) const;      // index 1-based, "" se invalido
  int rssiAt(int index) const;
  bool secureAt(int index) const;
  String bssidAt(int index) const;
  int channelAt(int index) const;
  String encryptionAt(int index) const;         // "open", "wpa2_psk", "wpa3_psk", ...
  int indexForSsid(const String &ssid) const;   // 1-based, 0 se nao achou no ultimo scan

  // Conexao normal (cliente).
  bool connect(const String &ssid, const String &pass, uint32_t timeoutMs = 15000);
  void disconnect();
  bool connected() const { return WiFi.status() == WL_CONNECTED; }
  String currentSsid() const { return WiFi.SSID(); }
  String ip() const { return WiFi.localIP().toString(); }
  String gateway() const { return WiFi.gatewayIP().toString(); }
  String subnet() const { return WiFi.subnetMask().toString(); }
  int currentRssi() const { return WiFi.RSSI(); }

  // Trava o radio no canal de uma rede ja escaneada, sem conectar nela.
  bool lockChannel(int index);
  void unlock();
  String lockedSsid() const { return lockedSsid_; }
  String lockedBssidString() const;
  int lockedChannel() const { return lockedChannel_; }

  // Sniff: escuta o BSSID travado, guarda os tipos de frame pedidos em cfg.
  void startSniff(const SniffConfig &cfg = SniffConfig{});
  void stopSniff();
  std::vector<SniffEntry> sniffCaptured() const { return sniffer_.snapshot(); }
  SniffStats sniffStats() const { return sniffer_.stats(); }
  PmfInfo sniffPmf() const { return sniffer_.pmf(); }

  // Deauth one-shot: manda `count` frames (poucos). target = "broadcast" ou um
  // MAC "AA:BB:CC:DD:EE:FF". frameType = "deauth" (padrao) ou "disassoc".
  bool sendDeauth(const String &target, uint16_t reason, const String &frameType = "deauth",
                  uint16_t count = 1);

  // Loop de deauth: reenvia poucos frames a cada intervalo pra manter o alvo
  // fora da rede (um deauth solto o cliente reconecta na hora). Roda "por cima"
  // do estado LOCKED; precisa chamar tick() no loop() principal.
  bool startDeauthLoop(const String &target, uint16_t reason,
                       const String &frameType = "deauth", uint32_t intervalMs = 200);
  void stopDeauthLoop();
  bool deauthLoopActive() const { return deauthLoopActive_; }
  uint32_t deauthLoopSent() const { return loopSentTotal_; }
  uint32_t deauthLoopInterval() const { return loopIntervalMs_; }
  String deauthLoopTargetString() const;
  void tick();  // reenvio periodico do loop; chamar sempre no loop() principal

  WifiState state() const { return state_; }
  String stateName() const;

private:
  int count_ = 0;
  WifiState state_ = WifiState::IDLE;
  uint8_t lockedBssid_[6] = {0};
  String lockedSsid_;
  int lockedChannel_ = 0;
  PacketSniffer sniffer_;

  // Loop de deauth (reenvio periodico por cima do estado LOCKED)
  bool deauthLoopActive_ = false;
  uint8_t loopTarget_[6] = {0};
  uint16_t loopReason_ = 1;
  uint8_t loopFc0_ = 0;
  uint32_t loopIntervalMs_ = 200;
  uint32_t lastLoopSend_ = 0;
  uint32_t loopSentTotal_ = 0;
};
