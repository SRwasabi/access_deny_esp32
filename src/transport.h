#pragma once
#include <Arduino.h>

// Canal de comunicacao (Serial, BLE, ...). O resto do firmware so conhece esta interface.
// Protocolo: uma mensagem JSON por linha, terminada em '\n'.
class Transport {
public:
  virtual ~Transport() {}
  virtual void begin() = 0;
  // Se houver uma mensagem completa pronta, copia para `out` e retorna true.
  virtual bool poll(String &out) = 0;
  // Envia uma resposta (o transport adiciona o '\n' final).
  virtual void send(const String &msg) = 0;
};
