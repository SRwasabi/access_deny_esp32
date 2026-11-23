#include <Arduino.h>
#include "wifi_manager.h"
#include "command_handler.h"
#include "serial_transport.h"
#include "ble_transport.h"

WifiManager wifi;
CommandHandler handler(wifi);
SerialTransport serialTransport;
BleTransport bleTransport;

Transport *transports[] = {&serialTransport, &bleTransport};

void setup() {
  serialTransport.begin();
  bleTransport.begin();
  wifi.begin();
  Serial.println("Pronto. Ex.: {\"cmd\":\"scan\"}");
}

void loop() {
  for (Transport *t : transports) {
    String line;
    if (t->poll(line)) {
      t->send(handler.handle(line));
    }
  }
  wifi.tick();  // reenvio periodico do loop de deauth, se estiver ativo
  delay(10);
}
