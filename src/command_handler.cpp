#include <ArduinoJson.h>
#include "command_handler.h"

static String errorJson(const char *msg) {
  JsonDocument doc;
  doc["ok"] = false;
  doc["error"] = msg;
  String out;
  serializeJson(doc, out);
  return out;
}

// bucket de sinal, so pra leitura humana -- o numero cru ja vai em "rssi".
static String signalQuality(int rssi) {
  if (rssi >= -50) return "excelente";
  if (rssi >= -60) return "boa";
  if (rssi >= -70) return "razoavel";
  return "fraca";
}

int CommandHandler::resolveScanIndex(JsonVariantConst req) {
  int index = req["index"] | 0;
  if (index != 0) return index;
  String ssid = req["ssid"] | "";
  if (ssid.length() == 0) return 0;
  return wifi_.indexForSsid(ssid);
}

String CommandHandler::handle(const String &line) {
  JsonDocument req;
  if (deserializeJson(req, line)) return errorJson("invalid_json");

  String cmd = req["cmd"] | "";
  if (cmd == "scan") return doScan();
  if (cmd == "connect") return doConnect(req);
  if (cmd == "status") return doStatus();
  if (cmd == "lock") return doLock(req);
  if (cmd == "unlock") return doUnlock();
  if (cmd == "sniff_start") return doSniffStart(req);
  if (cmd == "sniff_stop") return doSniffStop();
  if (cmd == "sniff_poll") return doSniffPoll();
  if (cmd == "sniff_stats") return doSniffStats();
  if (cmd == "deauth") return doDeauth(req);
  return errorJson("unknown_cmd");
}

String CommandHandler::doScan() {
  int n = wifi_.scan();
  JsonDocument doc;
  doc["ok"] = n >= 0;
  doc["count"] = wifi_.count();

  JsonArray nets = doc["networks"].to<JsonArray>();
  for (int i = 1; i <= wifi_.count(); i++) {
    JsonObject o = nets.add<JsonObject>();
    o["index"] = i;
    o["ssid"] = wifi_.ssidAt(i);
    o["bssid"] = wifi_.bssidAt(i);
    o["channel"] = wifi_.channelAt(i);

    int rssi = wifi_.rssiAt(i);
    JsonObject signal = o["signal"].to<JsonObject>();
    signal["rssi"] = rssi;
    signal["quality"] = signalQuality(rssi);

    JsonObject security = o["security"].to<JsonObject>();
    security["secure"] = wifi_.secureAt(i);
    security["encryption"] = wifi_.encryptionAt(i);
  }

  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doConnect(JsonVariantConst req) {
  // ssid livre tem prioridade (nao precisa ter sido escaneada); senao, resolve via scan.
  String ssid = req["ssid"] | "";
  if (ssid.length() == 0) {
    int index = resolveScanIndex(req);
    if (index != 0) ssid = wifi_.ssidAt(index);
  }
  if (ssid.length() == 0) return errorJson("missing_or_invalid_network");

  String pass = req["pass"] | "";
  bool ok = wifi_.connect(ssid, pass);

  JsonDocument doc;
  doc["ok"] = ok;
  doc["state"] = wifi_.stateName();
  if (ok) {
    JsonObject net = doc["network"].to<JsonObject>();
    net["ssid"] = ssid;
    net["ip"] = wifi_.ip();
    net["gateway"] = wifi_.gateway();
    net["subnet"] = wifi_.subnet();
    net["rssi"] = wifi_.currentRssi();
  } else {
    doc["ssid"] = ssid;
    doc["error"] = "connect_failed";
  }
  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doStatus() {
  JsonDocument doc;
  doc["ok"] = true;
  doc["state"] = wifi_.stateName();

  if (wifi_.connected()) {
    JsonObject net = doc["network"].to<JsonObject>();
    net["ssid"] = wifi_.currentSsid();
    net["ip"] = wifi_.ip();
    net["gateway"] = wifi_.gateway();
    net["subnet"] = wifi_.subnet();
    net["rssi"] = wifi_.currentRssi();
  }

  if (wifi_.state() == WifiState::LOCKED || wifi_.state() == WifiState::SNIFFING) {
    JsonObject target = doc["target"].to<JsonObject>();
    target["ssid"] = wifi_.lockedSsid();
    target["bssid"] = wifi_.lockedBssidString();
    target["channel"] = wifi_.lockedChannel();
  }

  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doLock(JsonVariantConst req) {
  int index = resolveScanIndex(req);
  if (index == 0) return errorJson("missing_index_or_ssid_not_found");

  bool ok = wifi_.lockChannel(index);
  JsonDocument doc;
  doc["ok"] = ok;
  doc["state"] = wifi_.stateName();
  if (ok) {
    JsonObject target = doc["target"].to<JsonObject>();
    target["index"] = index;
    target["ssid"] = wifi_.lockedSsid();
    target["bssid"] = wifi_.lockedBssidString();
    target["channel"] = wifi_.lockedChannel();
  } else {
    doc["error"] = "lock_failed";
  }
  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doUnlock() {
  wifi_.unlock();
  JsonDocument doc;
  doc["ok"] = true;
  doc["state"] = wifi_.stateName();
  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doSniffStart(JsonVariantConst req) {
  SniffConfig cfg;  // default: assoc + reassoc, sem probe
  if (req["types"].is<JsonArrayConst>()) {
    cfg.captureAssoc = false;
    cfg.captureReassoc = false;
    cfg.captureProbe = false;
    for (JsonVariantConst v : req["types"].as<JsonArrayConst>()) {
      String t = v.as<String>();
      if (t == "assoc") cfg.captureAssoc = true;
      else if (t == "reassoc") cfg.captureReassoc = true;
      else if (t == "probe") cfg.captureProbe = true;
    }
  }

  wifi_.startSniff(cfg);
  bool ok = wifi_.state() == WifiState::SNIFFING;

  JsonDocument doc;
  doc["ok"] = ok;
  doc["state"] = wifi_.stateName();
  if (ok) {
    JsonArray types = doc["types"].to<JsonArray>();
    if (cfg.captureAssoc) types.add("assoc");
    if (cfg.captureReassoc) types.add("reassoc");
    if (cfg.captureProbe) types.add("probe");
  } else {
    doc["error"] = "need_lock_first";
  }
  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doSniffStop() {
  wifi_.stopSniff();
  JsonDocument doc;
  doc["ok"] = true;
  doc["state"] = wifi_.stateName();
  String out;
  serializeJson(doc, out);
  return out;
}

// PMF (802.11w): se o alvo exige/suporta, um deauth nao assinado nao
// desconecta ninguem mesmo saindo com sucesso (esp_wifi_80211_tx -> ESP_OK).
static void writePmf(JsonObject &doc, const PmfInfo &pmf) {
  JsonObject o = doc["pmf"].to<JsonObject>();
  o["known"] = pmf.known;
  if (pmf.known) {
    o["capable"] = pmf.capable;
    o["required"] = pmf.required;
  }
}

String CommandHandler::doSniffPoll() {
  SniffStats s = wifi_.sniffStats();
  auto entries = wifi_.sniffCaptured();

  JsonDocument doc;
  doc["ok"] = true;
  doc["state"] = wifi_.stateName();

  JsonObject stats = doc["stats"].to<JsonObject>();
  stats["mgmt_seen"] = s.mgmtSeen;
  stats["beacon_seen"] = s.beaconSeen;
  stats["probe_req_seen"] = s.probeReqSeen;
  stats["assoc_req_seen"] = s.assocReqSeen;
  stats["reassoc_req_seen"] = s.reassocReqSeen;
  stats["matched"] = s.matched;

  JsonObject docObj = doc.as<JsonObject>();
  writePmf(docObj, wifi_.sniffPmf());

  JsonArray captured = doc["captured"].to<JsonArray>();
  for (auto &e : entries) {
    JsonObject o = captured.add<JsonObject>();
    o["type"] = e.type;
    o["mac"] = e.mac;
    if (e.ssid.length() > 0) o["ssid"] = e.ssid;
    o["target_match"] = e.targetMatch;
    if (e.pmf.known) writePmf(o, e.pmf);  // pmf que ESSE device pediu (so assoc/reassoc)
  }

  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doSniffStats() {
  SniffStats s = wifi_.sniffStats();
  JsonDocument doc;
  doc["ok"] = true;
  doc["state"] = wifi_.stateName();

  JsonObject stats = doc["stats"].to<JsonObject>();
  stats["mgmt_seen"] = s.mgmtSeen;
  stats["beacon_seen"] = s.beaconSeen;
  stats["probe_req_seen"] = s.probeReqSeen;
  stats["assoc_req_seen"] = s.assocReqSeen;
  stats["reassoc_req_seen"] = s.reassocReqSeen;
  stats["matched"] = s.matched;

  JsonObject docObj = doc.as<JsonObject>();
  writePmf(docObj, wifi_.sniffPmf());

  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doDeauth(JsonVariantConst req) {
  String target = req["target"] | "";
  if (target.length() == 0) return errorJson("missing_target");
  uint16_t reason = req["reason"] | 1;
  String type = req["type"] | "deauth";  // "deauth" (padrao) ou "disassoc"
  if (type != "deauth" && type != "disassoc") return errorJson("invalid_type");

  bool ok = wifi_.sendDeauth(target, reason, type);

  JsonDocument doc;
  doc["ok"] = ok;
  doc["state"] = wifi_.stateName();
  JsonObject docObj = doc.as<JsonObject>();
  writePmf(docObj, wifi_.sniffPmf());

  JsonObject deauth = doc["deauth"].to<JsonObject>();
  deauth["target"] = target;
  deauth["reason"] = reason;
  deauth["type"] = type;
  deauth["bssid"] = wifi_.lockedBssidString();
  if (!ok) doc["error"] = "deauth_failed_check_lock";

  String out;
  serializeJson(doc, out);
  return out;
}
