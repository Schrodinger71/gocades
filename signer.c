#include <cades.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// int main() {

int cades_sign_simple(const char* data, int data_len, unsigned char** out_sig, int* out_len) {
    // Define the data to be signed
    // BYTE data[] = "Hello, World!";
    // DWORD data_len = (DWORD)strlen((char*)data);

    // Use standard Windows CryptoAPI functions
    HCERTSTORE hStore = CertOpenSystemStoreA(0, "MY");
    if (!hStore) {
        printf("Failed to open certificate store using CertOpenSystemStoreA\n");
        return -1;
    }

    PCCERT_CONTEXT pCertContext = NULL;

    // Find the first certificate with a private key
    while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != NULL) {
        CRYPT_KEY_PROV_INFO* pKeyInfo = NULL;
        DWORD dwKeyProvInfoSize = 0;

        if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwKeyProvInfoSize)) {
            pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwKeyProvInfoSize);
            if (pKeyInfo && CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwKeyProvInfoSize)) {
                // Check certificate validity
                FILETIME ftSystemTime;
                GetSystemTimeAsFileTime(&ftSystemTime);
                if (CertVerifyTimeValidity(&ftSystemTime, pCertContext->pCertInfo) == 0) {
                    HCRYPTPROV hCryptProv = 0;
                    DWORD dwKeySpec = 0;
                    BOOL fCallerFreeProv = FALSE;
                    
                    if (CryptAcquireCertificatePrivateKey(pCertContext, 
                        CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, 
                        NULL, 
                        &hCryptProv, 
                        &dwKeySpec, 
                        &fCallerFreeProv)) {
                        CryptReleaseContext(hCryptProv, 0);
                        break; // Found a valid certificate with accessible private key
                    }
                }
            }
            if (pKeyInfo) {
                free(pKeyInfo);
                pKeyInfo = NULL;
            }
        }
    }

    if (!pCertContext) {
        printf("No suitable certificate found\n");
        CertCloseStore(hStore, 0);
        return -1;
    }

    printf("Using certificate for CAdES signing\n");

    // Use the actual OID for GOST R 34.11-2012 256
    CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = pCertContext;
    
    // Use GOST R 34.11-2012 256 bit hash algorithm OID
    signPara.HashAlgorithm.pszObjId = "1.2.643.7.1.1.2.2"; // GOST R 34.11-2012 256 bit

    const BYTE *pbToBeSigned[] = { data };
    DWORD cbToBeSigned[] = { data_len };

    printf("Trying CADES_BES with GOST hash...\n");
    
    CADES_SIGN_PARA cadesSignPara = { sizeof(cadesSignPara) };
    cadesSignPara.dwCadesType = CADES_BES;

    CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    if(CadesSignMessage(&para, FALSE, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage))
    {
        printf("GOST CAdES Signature created successfully!\n");
        
        // Print the signed message as hex
        printf("GOST CAdES signed message size: %d bytes\n", (int)pSignedMessage->cbData);
        
        // Print first few bytes as hex (for debugging)
        printf("First 10 bytes: ");
        for(DWORD i = 0; i < pSignedMessage->cbData && i < 10; i++) {
            printf("%02x ", pSignedMessage->pbData[i]);
        }
        printf("\n");

        if(CadesFreeBlob(pSignedMessage))
        {
            printf("CadesFreeBlob() succeeded\n");
        } else {
            printf("CadesFreeBlob() failed\n");
        }
    } else {
        printf("GOST CAdES failed\n");
        DWORD dwError = GetLastError();
        printf("GetLastError() returned: 0x%08X (%d)\n", (unsigned int)dwError, (int)dwError);
        
        // Try with SHA1 as fallback
        printf("Trying with SHA1 hash as fallback...\n");
        signPara.HashAlgorithm.pszObjId = "1.3.14.3.2.26"; // SHA1 OID
        
        if(CadesSignMessage(&para, FALSE, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage))
        {
            printf("SHA1 CAdES Signature created successfully!\n");
            
            // Print the signed message as hex
            printf("SHA1 CAdES signed message size: %d bytes\n", (int)pSignedMessage->cbData);
            
            if(CadesFreeBlob(pSignedMessage))
            {
                printf("CadesFreeBlob() succeeded\n");
            }
        } else {
            printf("SHA1 CAdES also failed\n");
            dwError = GetLastError();
            printf("GetLastError() returned: 0x%08X (%d)\n", (unsigned int)dwError, (int)dwError);
        }
    }

    // Clean up
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return 0;
}
