#ifndef __ACTION__HPP__
#define __ACTION__HPP__
#include <string>

int snp_node_register(std::string register_data);
int snp_node_attestation();
int snp_node_update_ms();
int snp_node_update_cert();

#endif