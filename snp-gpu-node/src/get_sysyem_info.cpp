#include "get_system_info.hpp"
#include <stdio.h>
#include <string.h>

#include <net/if.h> 
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <hv/json.hpp>
#include <iostream>
#include <fstream>
#include "bin-hex.hpp"
#include "snp-report.hpp"
using json = nlohmann::json;
using namespace std;

int get_os_info(char* os_info, int buffer_len){
    FILE *fp = fopen("/proc/version", "r");
    int i = 0, num_space = 1;
    if(!fp)
        return 1;
    fgets(os_info, buffer_len, fp);
    while(os_info[i] != 0){
        if(os_info[i] == ' '){
            if(num_space == 3){
                os_info[i] = 0;
                break;
            }
            num_space++;
        }
        if(os_info[i] == '\n'){
            os_info[i] = 0;
            break;
        }
        i++;
    }
    fclose(fp);
    return 0;
}

int get_cpu_info(char* cpu_info, int buffer_len){
    FILE *fp = fopen("/proc/cpuinfo", "r");
    char* sys_info;
    int i = 0;
    if(!fp)
        return 1;
    while(!feof(fp)){
        memset(cpu_info, 0, buffer_len);
        fgets(cpu_info, buffer_len, fp);
        if(strstr(cpu_info, "model name")){
            fclose(fp);
            while(cpu_info[i] != '\0'){
                if(cpu_info[i] == '\n'){
                    cpu_info[i] = '\0';
                    break;
                }
                i++;
            }
            sys_info = strtok(cpu_info, ":");
            sys_info = strtok(NULL, ":");
            memcpy(cpu_info, sys_info + 1, 100);
            return 0;
            break;
        }
    }
    fclose(fp);
    return 1;
}

int get_cpu_manufacture(char* cpu_info, int buffer_len){
    FILE *fp = fopen("/proc/cpuinfo", "r");
    char* sys_info;
    int i = 0;
    if(!fp)
        return 1;
    while(!feof(fp)){
        memset(cpu_info, 0, buffer_len);
        fgets(cpu_info, buffer_len, fp);
        if(strstr(cpu_info, "vendor_id")){
            fclose(fp);
            while(cpu_info[i] != '\0'){
                if(cpu_info[i] == '\n'){
                    cpu_info[i] = '\0';
                    break;
                }
                i++;
            }
            sys_info = strtok(cpu_info, ":");
            sys_info = strtok(NULL, ":");
            memcpy(cpu_info, sys_info + 1, 100);
            return 0;
            break;
        }
    }
    fclose(fp);
    return 2;
}

int get_ip(const char* name, char* ip, int buffer_len){
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    if(getifaddrs(&ifaddr) == -1)
        return 1;
    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
        if (ifa->ifa_addr == NULL)
           continue;
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET && (strcmp(ifa->ifa_name, name) == 0)){
            strcpy(ip, inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr));
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    freeifaddrs(ifaddr);
    return 2;
}

int get_mac(const char* name, char* mac, int buffer_len){
    struct ifreq ifreq;
    int sock;
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return 1;
    strcpy(ifreq.ifr_name, name);
    if(ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0)
        return 2;
    buffer_len -= snprintf(mac, buffer_len, "%X:%X:%X:%X:%X:%X", 
    (unsigned char) ifreq.ifr_hwaddr.sa_data[0], 
    (unsigned char) ifreq.ifr_hwaddr.sa_data[1], 
    (unsigned char) ifreq.ifr_hwaddr.sa_data[2], 
    (unsigned char) ifreq.ifr_hwaddr.sa_data[3], 
    (unsigned char) ifreq.ifr_hwaddr.sa_data[4], 
    (unsigned char) ifreq.ifr_hwaddr.sa_data[5]);
    if(buffer_len <= 0)
        return 3;
    return 0;
}

int get_manufacture(char* buffer, int buffer_len){
    FILE *fp = fopen("/sys/class/dmi/id/board_vendor", "r");
    int i = 0;
    if(!fp)
        return 1;
    fgets(buffer, buffer_len, fp);
        while(buffer[i] != 0){
        if(buffer[i] == '\n'){
            buffer[i] = 0;
            break;
        }
        i++;
    }
    fclose(fp);
    return 0;
}

int execmd(const char* cmd, char* result){
    char buffer[128];
    FILE* pipe = popen(cmd, "r");
    if(!pipe)
        return 1;

    while(!feof(pipe)){
        if(fgets(buffer, 128, pipe))
            strcat(result, buffer);
    }
    pclose(pipe);
    return 0;
}

void remove_enter(char* buffer){
    int i = 0;
    for(i = 0; buffer[i] != 0 && buffer[i] != '\n'; ++i);
    buffer[i] = 0;
}

void out_put_system_info(){
    json info;
    char buffer[1024];
    memset(buffer, 0x00, 1024);
    info["type"] = 7;
    get_os_info(buffer, 1024);
    remove_enter(buffer);
    info["os"] = buffer;
    memset(buffer, 0x00, 1024);
    info["manufacture"] = "AMD";
    get_cpu_info(buffer, 1024);
    remove_enter(buffer);
    info["devinfo"] = buffer;
    memset(buffer, 0x00, 1024);
    // info["ip"] = "192.168.88.138";
    get_mac("enp0s2", buffer, 1024);
    remove_enter(buffer);
    info["mac"] = buffer;
    memset(buffer, 0x00, 1024);
    get_cpu_manufacture(buffer, 1024);
    remove_enter(buffer);
    info["name"] = buffer;
    memset(buffer, 0x00, 1024);
    remove_enter(buffer);
    execmd("whoami", buffer);
    remove_enter(buffer);
    info["host"] = buffer;
    memset(buffer, 0x00, 1024);
    execmd("curl ifconfig.net/country-iso", buffer);
    remove_enter(buffer);
    info["area"] = buffer;
    memset(buffer, 0x00, 1024);


    struct stat file_buffer;
    if(stat("../information/attestation-report.bin", &file_buffer)){
        printf("Get report.\n");
        execmd("/home/vonsky/.cargo/bin/snpguest report ../information/attestation-report.bin ../information/random-request-file.txt --random", buffer);
    }
        
    if(stat("../information/ask.der", &file_buffer) || stat("../information/ark.der", &file_buffer)){
        printf("Get cert.\n");
        execmd("/home/vonsky/.cargo/bin/snpguest fetch ca der milan ../information", buffer);
    }
        
    if(stat("../information/vcek.der", &file_buffer)){
        printf("Get cek.\n");
        execmd("/home/vonsky/.cargo/bin/snpguest fetch vcek der milan ../information ../information/attestation-report.bin", buffer);
    }
        
    int ark_len;
    char* ark_cert = file2hex("../information/ark.der", &ark_len);
    int ask_len;
    char* ask_cert = file2hex("../information/ask.der", &ask_len);
    int cek_len;
    char* cek_cert = file2hex("../information/vcek.der", &cek_len);

    SNPReport* snp_report = dump_report_from_file("../information/attestation-report.bin");

    char* measurement = bin2hex(snp_report->measurement, SNP_MEASUTEMENT_LENGTH);

    json snp ={
        {"cek_cert", cek_cert},
        {"cek_cert_size", cek_len},
        {"ark_cert", ark_cert},
        {"ark_cert_size", ark_len},
        {"ask_cert", ask_cert},
        {"ask_cert_size", ask_len},
        {"tcb_info",{
                {"measurement", measurement},
                {"abi_major",snp_report->guest_policy.abi_major},
                {"abi_minor",snp_report->guest_policy.abi_minor},
                {"boot_loader",snp_report->current_tcb.boot_loader},
                {"committed_build",snp_report->committed_version.build},
                {"committed_major",snp_report->committed_version.major},
                {"committed_minor",snp_report->committed_version.minor},
                {"current_build",snp_report->current_version.build},
                {"current_major",snp_report->current_version.major},
                {"current_minor",snp_report->current_version.minor},
                {"guest_svn",snp_report->guest_svn},
                {"microcode",snp_report->current_tcb.microcode},
                {"debug_allowed",(snp_report->guest_policy.info_1 >> 3) & 0x1},
                {"migrate_ma",(snp_report->guest_policy.info_1 >> 2) & 0x1},
                {"smt_allowed",snp_report->guest_policy.info_1 & 0x1},
                {"smt_enabled",snp_report->platform_info.info & 0x1},
                {"snp",snp_report->current_tcb.snp},
                {"signature_algorithm",(snp_report->sig_algo == 1) ? "secp384r1" : "UNKNOWN"},
                {"single_socket",(snp_report->guest_policy.info_1 >> 4) & 0x1},
                {"tee",snp_report->current_tcb.tee},
                {"tsme_enabled",(snp_report->platform_info.info >> 1) & 0x1},
                {"vmpl",(int)snp_report->vmpl},
                {"version",snp_report->version}
        }}
    };
    info["snp"] = snp;

    char x_point[97];
    char y_point[97];
    memcpy(x_point, cek_cert + 776, 96);
    x_point[96] = 0;
    memcpy(y_point, cek_cert + 776 + 96, 96);
    y_point[96] = 0;

    json snp_ak = {
        {"x_point", x_point},
        {"x_size", 96},
        {"y_point", y_point},
        {"y_size", 96}
    };
    info["ak"] = snp_ak;

    ofstream f("../information/system-info.json", ios::out);
    f << info.dump(2);

    if(ark_cert != nullptr)
        delete [] ark_cert;
    if(ask_cert != nullptr)
        delete [] ask_cert;
    if(cek_cert != nullptr)
        delete [] cek_cert;
    if(snp_report != nullptr)
        delete [] snp_report;
    if(measurement != nullptr)
        delete [] measurement;
    f.close();
}