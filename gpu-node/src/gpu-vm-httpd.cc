#include <hv/HttpServer.h>
#include <hv/hthread.h>
#include <hv/hasync.h>
#include <iostream>
#include <fstream>
#include <string>
#include "tpm.h"
#include "get-hash.h"

#define MAX_FILE_NUM 100
#define RC_SUCCESS 0
#define RC_GPU_MEASUTE_FAIL 9001
#define RC_REQUEST_ERROR 9002
#define RC_TPM_QUOTE_FAIL 9003

using json = nlohmann::json;

TPMinstance* tpm_instance;

void router_init(HttpService* router){
    router->GET("/ping", [](const HttpContextPtr& ctx) {
        std::string resp = "pong";
        return ctx->send(resp);
    });

    router->GET("/information", [](const HttpContextPtr& ctx){
        std::ifstream file_list;
        std::string line;
        json resp, tpm_info;
        int num_file = 0;
        char* argv[MAX_FILE_NUM];
        char* result;
        int status = 0;
        std::ifstream f("../tpm/platinfo.json");

        resp = json::parse(f);
        f.close();
        file_list.open("../config/measurement-list", std::ios::in);
        while(getline(file_list, line)){
            argv[num_file] = (char*)malloc(line.length() + 1);
            memcpy(argv[num_file], line.c_str(), line.length() + 1);
            num_file++;
        }
        file_list.close();
        result = get_hash_result(num_file, argv);
        if(!result)
            status = 1091;
        else{
            resp["data"]["tpm"]["measurement"] = json::parse(result);
            free(result);
        }
        while(num_file > 0){
            num_file--;
            free(argv[num_file]);
        }
        resp["status"] = status;
        return ctx->send(resp.dump(2));
    });

    router->POST("/quote", [](const HttpContextPtr& ctx){
        std::ifstream file_list, f;
        std::string line, randnum, mask;
        json resp, hash_result, request, tpm_info;
        int num_file = 0, randnum_len;
        char* argv[MAX_FILE_NUM];
        char* result = NULL;
        FILE* p = NULL;

        f.open("../tpm/platinfo.json", std::ios::in);
        tpm_info = json::parse(f);
        f.close();
        resp["ak_pubkey"] = tpm_info["ak_pubkey"]["tpm"];

        file_list.open("../config/measurement-list", std::ios::in);
        while(getline(file_list, line)){
            argv[num_file] = (char*)malloc(line.length() + 1);
            memcpy(argv[num_file], line.c_str(), line.length() + 1);
            num_file++;
        }
        file_list.close();
        result = get_hash_result(num_file, argv);
        
        if(!result){
            resp["status"] = RC_GPU_MEASUTE_FAIL;
            goto err;
        }
        try{
            hash_result = json::parse(result);
        }
        catch(...){
            resp["status"] = RC_GPU_MEASUTE_FAIL;
            goto err;
        }

        p = popen("tpm2_pcrreset 16 --tcti=mssim","r");
        pclose(p);
        line = "tpm2_pcrextend 16:sm3_256=";
        line += hash_result["total_hash"];
        line += " --tcti=mssim";
        std::cout << line << std::endl;
        p = popen(line.c_str(),"r");
        pclose(p);
        resp["evidence"]["tpm"]["file-hash"] = hash_result;

        try{
            request = json::parse(ctx->body());
            request["nonce"].get_to(randnum);
            request["nonce_size"].get_to(randnum_len);
            request["mask"].get_to(mask);
        }
        catch(...){
            resp["status"] = RC_REQUEST_ERROR;
            goto err;
        }
        free(result);
        result = NULL;
        if(tpm_instance->create_quote(mask.c_str(), randnum.c_str(), &result)){
            resp["status"] = RC_TPM_QUOTE_FAIL;
            goto err;
        }
        resp["status"] = RC_SUCCESS;
        resp["evidence"]["tpm"]["quote"] = result;
        resp["evidence"]["tpm"]["quote_size"] = strlen(result);
        
err:
        while(num_file > 0){
            num_file--;
            free(argv[num_file]);
        }
        if(result)
            free(result);
        return ctx->send(resp.dump(2));
    });
}

int main(){
    HttpService router;
    hv::HttpServer server;
    router_init(&router);
    tpm_instance = new(TPMinstance);
    tpm_instance->tpm_init(0);
    server.service = &router;
    server.https_port = 8080;

    hssl_ctx_opt_t param;
    memset(&param, 0, sizeof(param));
    param.crt_file = "../config/server.crt";
    param.key_file = "../config/server.key";
    param.endpoint = HSSL_SERVER;
    if (server.newSslCtx(&param) != 0) {
        fprintf(stderr, "new SSL_CTX failed!\n");
        return -20;
    }
    server.start();

    while (getchar() != '\n');
    hv::async::cleanup();
    delete tpm_instance;
    return 0;
}