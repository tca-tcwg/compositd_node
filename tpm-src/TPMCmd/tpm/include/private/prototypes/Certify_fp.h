
// FILE GENERATED BY TpmExtractCode: DO NOT EDIT

#if CC_Certify  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_CERTIFY_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_CERTIFY_FP_H_

// Input structure definition
typedef struct
{
    TPMI_DH_OBJECT  objectHandle;
    TPMI_DH_OBJECT  signHandle;
    TPM2B_DATA      qualifyingData;
    TPMT_SIG_SCHEME inScheme;
} Certify_In;

// Output structure definition
typedef struct
{
    TPM2B_ATTEST   certifyInfo;
    TPMT_SIGNATURE signature;
} Certify_Out;

// Response code modifiers
#    define RC_Certify_objectHandle   (TPM_RC_H + TPM_RC_1)
#    define RC_Certify_signHandle     (TPM_RC_H + TPM_RC_2)
#    define RC_Certify_qualifyingData (TPM_RC_P + TPM_RC_1)
#    define RC_Certify_inScheme       (TPM_RC_P + TPM_RC_2)

// Function prototype
TPM_RC
TPM2_Certify(Certify_In* in, Certify_Out* out);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_CERTIFY_FP_H_
#endif    // CC_Certify
