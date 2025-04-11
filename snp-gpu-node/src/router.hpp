#ifndef ROUTER_H
#define ROUTER_H

#include <iostream>
#include <hv/HttpServer.h>

typedef struct _NetworkConfig{
    uint16_t listen_port;
    std::string soc_ip;
    uint16_t soc_port;
    std::string as_ip;
    uint16_t as_port;
    std::string kms_ip;
    uint16_t kms_port;
    std::string gpu_ip;
    uint16_t gpu_port;
    std::string host_ip;
    uint16_t host_port;
} NetworkConfig;


void router_init(HttpService* router);
void server_init();

#endif