#pragma once
#include "XTTPSession.h"

class ProtocolHandler {
public:
    static void ParseRequest(const std::string& raw);
    static void ParseResponse(const std::string& raw);
};
