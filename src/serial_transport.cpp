#include "serial_transport.h"

void SerialTransport::begin() {
  Serial.begin(115200);
}

bool SerialTransport::poll(String &out) {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      if (buf_.length() == 0) continue;
      out = buf_;
      buf_ = "";
      return true;
    }
    buf_ += c;
  }
  return false;
}

void SerialTransport::send(const String &msg) {
  Serial.println(msg);
}
