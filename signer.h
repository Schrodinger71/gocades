#ifndef SIGNER_H
#define SIGNER_H

int cades_sign_simple(const char* data, int data_len, unsigned char** out_sig, int* out_len);

#endif
