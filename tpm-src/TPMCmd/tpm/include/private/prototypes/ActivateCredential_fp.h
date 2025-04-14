
// FILE GENERATED BY TpmExtractCode: DO NOT EDIT

#if CC_ActivateCredential  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_ACTIVATECREDENTIAL_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_ACTIVATECREDENTIAL_FP_H_

// Input structure definition
typedef struct
{
    TPMI_DH_OBJECT         activateHandle;
    TPMI_DH_OBJECT         keyHandle;
    TPM2B_ID_OBJECT        credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
} ActivateCredential_In;

// Output structure definition
typedef struct
{
    TPM2B_DIGEST certInfo;
} ActivateCredential_Out;

// Response code modifiers
#    define RC_ActivateCredential_activateHandle (TPM_RC_H + TPM_RC_1)
#    define RC_ActivateCredential_keyHandle      (TPM_RC_H + TPM_RC_2)
#    define RC_ActivateCredential_credentialBlob (TPM_RC_P + TPM_RC_1)
#    define RC_ActivateCredential_secret         (TPM_RC_P + TPM_RC_2)

// Function prototype
TPM_RC
TPM2_ActivateCredential(ActivateCredential_In* in, ActivateCredential_Out* out);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_ACTIVATECREDENTIAL_FP_H_
#endif    // CC_ActivateCredential
