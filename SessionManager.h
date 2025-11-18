#pragma once
#include <string>

struct XTTPSession {
    std::string session_id;
    std::string client_id;
    bool active;
    std::string handshake_status;
    std::string cert_info;
};
