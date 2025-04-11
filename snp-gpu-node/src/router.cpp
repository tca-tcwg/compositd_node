#include <fstream>
#include <hv/HttpServer.h>
#include <hv/json.hpp>
#include <hv/requests.h>
#include <string>
#include <string.h>
#include <iostream>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>  
#include <stdlib.h>

#include "router.hpp"
#include "get_system_info.hpp"
#include "action.hpp"
#include "command_error.h"

extern NetworkConfig global_net_config;
using json = nlohmann::json;
using namespace std;

void server_init(){
    std::ifstream f("../information/network_config.json");
    json json_data = json::parse(f);
    global_net_config.listen_port = json_data["listen_port"];

    global_net_config.soc_port = json_data["SOC_PORT"];
    global_net_config.as_port = json_data["AS_PORT"];
    global_net_config.kms_port = json_data["KMS_PORT"];
    global_net_config.gpu_port = json_data["GPU_PORT"];
    global_net_config.host_port = json_data["HOST_PORT"];

    global_net_config.soc_ip = json_data["SOC_IP"];
    global_net_config.as_ip = json_data["AS_IP"];
    global_net_config.kms_ip = json_data["KMS_IP"];
    global_net_config.gpu_ip = json_data["GPU_IP"];
    global_net_config.host_ip = json_data["HOST_IP"];

    cout << "Initialization Information\n" << 
    "Listening Address: 0.0.0.0:" << global_net_config.listen_port << endl 
    << "SOC Address: "<< global_net_config.soc_ip << ':' << global_net_config.soc_port << endl
    << "AS Address: "<< global_net_config.as_ip << ':' << global_net_config.as_port << endl
    << "KMS Address: "<< global_net_config.kms_ip << ':' << global_net_config.kms_port << endl
    << "GPU Address: "<< global_net_config.gpu_ip << ':' << global_net_config.gpu_port << endl;

    f.close();
}

void router_init(HttpService* router){
    router->GET("/ping", [](const HttpContextPtr& ctx) {
        return ctx->send("pong");
    });

    router->GET("/commands/register", [](const HttpContextPtr& ctx) {
        cout << "Register\n"; 
        string id;
        json get_data = ctx->params();
        get_data["node_id"].get_to(id);
        json resp;

        string gpu_address = "https://" + global_net_config.gpu_ip + ":" + to_string(global_net_config.gpu_port) + "/information"; 
        auto r = requests::get(gpu_address.c_str());

        cout << r->body << endl; 
        json register_data = json::parse(r->body);

        out_put_system_info();
        ifstream f("../information/system-info.json");
        json sys_info = json::parse(f);
        f.close();
        
        char info_key[9][15] = {"area", "devinfo", "host", "ip",
            "mac", "manufacture", "name", "os", "type"};
        for(int i = 0; i < 9; ++i){
            register_data[info_key[i]] = sys_info[info_key[i]];
        }
        register_data["data"]["snp"] = sys_info["snp"];
        register_data["ak_pubkey"]["snp"] = sys_info["ak"];
        register_data["node_id"] = stoi(id);
        register_data["ip"] = global_net_config.host_ip;
        register_data["port"] = global_net_config.host_port;

        int ret = snp_node_register(register_data.dump(2));
        if(ret && ret != RC_REGISTER_NODE_REGISTER_SUCCEED){
            printf("Register error:%d\n", ret);
        }
        else{
            ret = RC_REGISTER_NODE_REGISTER_SUCCEED;
            f.open("../information/nodedat.json");
            json node_dat = json::parse(f);
            resp["uuid"] = node_dat["uuid"];
            f.close();
        }
        resp["node_status"] = ret;
        if(ret){
            ofstream outfile("/home/vonsky/dat/token", ios::out | ios::trunc);
            outfile.close();
        }
        return ctx->send(resp.dump(2));
    });

    router->GET("/commands/attestation", [](const HttpContextPtr& ctx) {
        json resp; 
        cout << "attestation\n"; 
        int ret = snp_node_attestation();

        if(ret){
            printf("Attestation error:%d\n", ret);
        }
        
        resp["node_attestation_status"] = ret;
        return ctx->send(resp.dump(2));
    }); 
}