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
//   {"cmd":"lock","index":2}                        (trava o canal da rede, sem conectar)
//   {"cmd":"lock","ssid":"MinhaRede"}               (acha o index pelo ssid no ultimo scan)
//   {"cmd":"unlock"}
//   {"cmd":"sniff_start"}                           (precisa ja estar locked; tipos default: assoc+reassoc)
//   {"cmd":"sniff_start","types":["assoc","reassoc","probe"]}
//   {"cmd":"sniff_stop"}
//   {"cmd":"sniff_poll"}                             (stats + pmf + ultimos eventos guardados, sem limpar o buffer)
//   {"cmd":"sniff_stats"}                            (stats + pmf, sem a lista de eventos)
//   -- "pmf" (em sniff_poll/sniff_stats/deauth): lido do RSN IE do beacon do
//      alvo. Se "required":true, deauth nao assinado nunca vai desconectar
//      ninguem -- nao e bug nosso, e protecao real do 802.11w.
//   {"cmd":"deauth","target":"broadcast","reason":1}                (one-shot; type default: "deauth", count default: 1, max 100)
//   {"cmd":"deauth","target":"AA:BB:CC:DD:EE:FF","reason":1,"type":"disassoc"}
//   {"cmd":"deauth_loop_start","target":"AA:BB:CC:DD:EE:FF","interval":200}  (reenvia a cada 200ms ate parar)
//   {"cmd":"deauth_loop_stop"}                                       (para o loop)
class CommandHandler {
public:
  explicit CommandHandler(WifiManager &wifi) : wifi_(wifi) {}
  String handle(const String &line);

private:
  // index direto, ou acha pelo ssid no ultimo scan. Devolve 0 se nao achou.
  int resolveScanIndex(JsonVariantConst req);

  String doScan();
  String doConnect(JsonVariantConst req);
  String doStatus();
  String doLock(JsonVariantConst req);
  String doUnlock();
  String doSniffStart(JsonVariantConst req);
  String doSniffStop();
  String doSniffPoll();
  String doSniffStats();
  String doDeauth(JsonVariantConst req);
  String doDeauthLoopStart(JsonVariantConst req);
  String doDeauthLoopStop();
  WifiManager &wifi_;
};
