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

String CommandHandler::handle(const String &line) {
  JsonDocument req;
  if (deserializeJson(req, line)) return errorJson("invalid_json");

  String cmd = req["cmd"] | "";
  if (cmd == "scan") return doScan();
  if (cmd == "connect") return doConnect(req);
  if (cmd == "status") return doStatus();
  return errorJson("unknown_cmd");
}

String CommandHandler::doScan() {
  int n = wifi_.scan();
  JsonDocument doc;
  doc["ok"] = n >= 0;
  JsonArray nets = doc["networks"].to<JsonArray>();
  for (int i = 1; i <= wifi_.count(); i++) {
    JsonObject o = nets.add<JsonObject>();
    o["index"] = i;
    o["ssid"] = wifi_.ssidAt(i);
    o["rssi"] = wifi_.rssiAt(i);
    o["secure"] = wifi_.secureAt(i);
  }
  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doConnect(JsonVariantConst req) {
  String ssid = req["ssid"] | "";
  if (ssid.length() == 0 && req["index"].is<int>()) {
    ssid = wifi_.ssidAt(req["index"].as<int>());
  }
  if (ssid.length() == 0) return errorJson("missing_or_invalid_network");

  String pass = req["pass"] | "";
  bool ok = wifi_.connect(ssid, pass);

  JsonDocument doc;
  doc["ok"] = ok;
  doc["ssid"] = ssid;
  if (ok) doc["ip"] = wifi_.ip();
  else doc["error"] = "connect_failed";
  String out;
  serializeJson(doc, out);
  return out;
}

String CommandHandler::doStatus() {
  JsonDocument doc;
  doc["ok"] = true;
  doc["connected"] = wifi_.connected();
  if (wifi_.connected()) {
    doc["ssid"] = wifi_.currentSsid();
    doc["ip"] = wifi_.ip();
  }
  String out;
  serializeJson(doc, out);
  return out;
}
