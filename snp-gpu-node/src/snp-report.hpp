#ifndef __SNP_REPORT_HPP__
#define __SNP_REPORT_HPP__

#include <stdint.h>
#include <fstream>

#define SNP_MEASUTEMENT_LENGTH 48

struct _tcb_version{
    uint8_t boot_loader;
    uint8_t tee;
    uint32_t reverse;
    uint8_t snp;
    uint8_t microcode;
} __attribute__((packed));
typedef struct _tcb_version TcbVersion;

struct _firmware_version{
    uint8_t build;
    uint8_t minor;
    uint8_t major;
    uint8_t reverse;
} __attribute__((packed));
typedef struct _firmware_version FirmwareVersion;

struct _snp_signature{
    uint8_t sig_r[48];
    uint8_t reverse0[24];
    uint8_t sig_s[48];
    uint8_t reverse1[24];
} __attribute__((packed));
typedef struct _snp_signature SNPSignature;

struct _guest_policy{
    uint8_t abi_minor;
    uint8_t abi_major;
    uint8_t info_1;
    // smt, reserved, migrate_ma, debug, 
    // single_socket, cxl_allow, mem_aes_256_xts, rapl_dis
    uint8_t info_2;
    // ciphertext_hiding, reserved[7]
    uint8_t reverse[4];
} __attribute__((packed));
typedef struct _guest_policy GuestPolicy;

struct _platform_info{
    uint8_t info;
    // smt_en, tsme_en, ecc_en, rapl_dis, ciphertext_hiding_en, reserved[3]
    uint8_t reverse[7];
} __attribute__((packed));
typedef struct _platform_info PlatformInfo;

struct _SNPReport{
    uint8_t version;
    uint8_t guest_svn; 
    uint8_t reverse0[6];
    GuestPolicy guest_policy;
    uint8_t family_id[16];
    uint8_t image_id[16];
    uint32_t vmpl;
    uint32_t sig_algo;
    TcbVersion current_tcb;
    PlatformInfo platform_info;
    uint32_t key_info;
    uint32_t reverse1;
    uint8_t report_data[64];
    uint8_t measurement[48];
    uint8_t host_data[32];
    uint8_t id_key_digest[48];
    uint8_t author_key_digest[48];
    uint8_t report_id[32];
    uint8_t report_id_mig_agent[32];
    TcbVersion reported_tcb;
    uint8_t reverse2[24];
    uint8_t chip_id[64];
    TcbVersion committed_tcb;
    FirmwareVersion current_version;
    FirmwareVersion committed_version;
    TcbVersion launch_tcb;
    SNPSignature signature;
} __attribute__((packed));
typedef struct _SNPReport SNPReport;

SNPReport* dump_report_from_file(const char* file_name){
    std::ifstream f(file_name, std::ios::in | std::ios::binary);
    if(!f)
        return nullptr;
    SNPReport* report = new SNPReport;
    f.read((char*)report, sizeof(SNPReport));
    f.close();
    return report;
}
#endif