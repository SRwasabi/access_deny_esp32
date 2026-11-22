#pragma once
#include <Arduino.h>
#include <vector>
#include <esp_wifi.h>

// Contadores de diagnostico: quantos frames de cada tipo o sniff ja viu no total,
// independente de terem sido guardados ou nao.
struct SniffStats {
  uint32_t mgmtSeen = 0;
  uint32_t beaconSeen = 0;
  uint32_t probeReqSeen = 0;
  uint32_t assocReqSeen = 0;    // qualquer BSSID
  uint32_t reassocReqSeen = 0;  // qualquer BSSID
  uint32_t matched = 0;         // assoc/reassoc cujo BSSID bate com o alvo travado
};

// Quais tipos de frame o sniff guarda no buffer (alem de sempre contar nas stats).
struct SniffConfig {
  bool captureAssoc = true;
  bool captureReassoc = true;
  bool captureProbe = false;
};

// O que um beacon ou association request anuncia sobre PMF (802.11w). Se o
// alvo exige/suporta PMF, um deauth nao assinado e ignorado pelo cliente
// mesmo que o ESP mande o frame com sucesso (esp_wifi_80211_tx -> ESP_OK).
struct PmfInfo {
  bool known = false;     // conseguimos ler o RSN IE desse frame
  bool capable = false;   // MFPC: suporta PMF (pode ou nao aceitar)
  bool required = false;  // MFPR: exige PMF -- deauth nao assinado NUNCA vai funcionar
};

// Um evento guardado no buffer circular.
struct SniffEntry {
  String type;        // "assoc_req" | "reassoc_req" | "probe_req"
  String mac;          // MAC de origem do frame (addr2)
  String ssid;          // so em probe_req direcionado; "" se nao se aplica/coringa
  bool targetMatch;     // assoc/reassoc: BSSID == alvo travado. probe: SSID pedido == SSID do alvo.
  PmfInfo pmf;           // so em assoc/reassoc: PMF que ESSE dispositivo pediu pra sessao dele
};

// Modo promiscuo: escuta o canal ja travado pelo WifiManager e guarda os eventos
// que interessam, num buffer circular de tamanho fixo (nao estoura RAM).
class PacketSniffer {
public:
  void begin(const uint8_t bssid[6], const String &ssid, const SniffConfig &cfg);
  void end();

  std::vector<SniffEntry> snapshot() const { return buffer_; }
  SniffStats stats() const { return stats_; }
  PmfInfo pmf() const { return pmf_; }

private:
  static void onPacket(void *buf, wifi_promiscuous_pkt_type_t type);
  void handlePacket(const wifi_promiscuous_pkt_t *pkt);
  void push(const SniffEntry &entry);

  static const size_t kMaxEntries = 40;

  static PacketSniffer *instance_;
  uint8_t targetBssid_[6] = {0};
  String targetSsid_;
  SniffConfig cfg_;
  std::vector<SniffEntry> buffer_;
  SniffStats stats_;
  PmfInfo pmf_;
};
