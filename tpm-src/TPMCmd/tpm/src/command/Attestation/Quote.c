#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "Quote_fp.h"

#if CC_Quote  // Conditional expansion of this file

/*(See part 3 specification)
// quote PCR values
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY              'signHandle' does not reference a signing key;
//      TPM_RC_SCHEME           the scheme is not compatible with sign key type,
//                              or input scheme is not compatible with default
//                              scheme, or the chosen scheme is not a valid
//                              sign scheme

//extern int mytest();
#include <dlfcn.h>
#define SNP_REPORT_LEN 0x500
int (*get_report)(unsigned char* usr_data, int vmpl, int version, unsigned char* report) = NULL;

TPM_RC
TPM2_Quote(Quote_In*  in,  // IN: input parameter list
           Quote_Out* out  // OUT: output parameter list
)
{
    TPMI_ALG_HASH hashAlg;
    TPMS_ATTEST   quoted;
    OBJECT*       signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_Quote_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_Quote_inScheme;

    // Command Output

    // Filling in attest information
    // Common fields
    // FillInAttestInfo may return TPM_RC_SCHEME or TPM_RC_KEY
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &quoted);

    // Quote specific fields
    // Attestation type
    quoted.type = TPM_ST_ATTEST_QUOTE;

    // Get hash algorithm in sign scheme.  This hash algorithm is used to
    // compute PCR digest. If there is no algorithm, then the PCR cannot
    // be digested and this command returns TPM_RC_SCHEME
    hashAlg = in->inScheme.details.any.hashAlg;

    if(hashAlg == TPM_ALG_NULL)
        return TPM_RCS_SCHEME + RC_Quote_inScheme;

    // Compute PCR digest
    PCRComputeCurrentDigest(
        hashAlg, &in->PCRselect, &quoted.attested.quote.pcrDigest);

    // Copy PCR select.  "PCRselect" is modified in PCRComputeCurrentDigest
    // function
    quoted.attested.quote.pcrSelect = in->PCRselect;

    /**
     * Add here
     * 
     */
    if(get_report == NULL)
    {
        void* fd = dlopen("./libsnp_guest_ioctl.so", RTLD_LAZY);
        get_report = dlsym(fd, "get_report");
    }

    unsigned char usr_data[64];
    //unsigned char report[SNP_REPORT_LEN];
    memset(usr_data, 0x00, 64);
    memset(quoted.attested.quote.teeReport.report, 0x00, SNP_REPORT_LEN);
    int ret = get_report(usr_data, 1, 1, quoted.attested.quote.teeReport.report);

    if(ret <0)
    {
        puts("Error in get tee repert");
        exit(-1);
    }
    quoted.attested.quote.teeReport.size = SNP_REPORT_LEN;
    printf("%llx\n",*(unsigned long long *)quoted.attested.quote.teeReport.report);
    //printf("result : %d\n", ret);



    // FILE * s_ReportFile                 = fopen("TEE_REPORT", "r+b");
    // if(s_ReportFile == NULL) exit(-1);
    // unsigned bytesRead = fread(quoted.attested.quote.teeReport.report, sizeof(char), MAX_TEE_REPORT_SIZE, s_ReportFile);
    // if (!feof(s_ReportFile)) {
    //     fclose(s_ReportFile);
    //     exit(-1);
    // }
    // fclose(s_ReportFile);
    // quoted.attested.quote.teeReport.size = bytesRead;


    //mytest();

    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject,
                          &in->inScheme,
                          &quoted,
                          &in->qualifyingData,
                          &out->quoted,
                          &out->signature);
}

#endif  // CC_Quote