
// FILE GENERATED BY TpmExtractCode: DO NOT EDIT

#if CC_NV_UndefineSpace  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_NV_UNDEFINESPACE_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_NV_UNDEFINESPACE_FP_H_

// Input structure definition
typedef struct
{
    TPMI_RH_PROVISION        authHandle;
    TPMI_RH_NV_DEFINED_INDEX nvIndex;
} NV_UndefineSpace_In;

// Response code modifiers
#    define RC_NV_UndefineSpace_authHandle (TPM_RC_H + TPM_RC_1)
#    define RC_NV_UndefineSpace_nvIndex    (TPM_RC_H + TPM_RC_2)

// Function prototype
TPM_RC
TPM2_NV_UndefineSpace(NV_UndefineSpace_In* in);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_NV_UNDEFINESPACE_FP_H_
#endif    // CC_NV_UndefineSpace
