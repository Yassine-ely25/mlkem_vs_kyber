#include <oqs/oqs.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

double time_diff_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e3 + (end.tv_nsec - start.tv_nsec) / 1e6;
}

int main() {

    int N_RUNS = 1000;
    struct timespec t1, t2;

    printf("------------- Kyber-KEM-768 --------------\n");

    // Initialize Kyber 
    OQS_KEM *kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    uint8_t *pk_kyber = malloc(kyber->length_public_key);
    uint8_t *sk_kyber = malloc(kyber->length_secret_key);
    uint8_t *ct_kyber = malloc(kyber->length_ciphertext);
    uint8_t *ss_enc_kyber = malloc(kyber->length_shared_secret);
    uint8_t *ss_dec_kyber = malloc(kyber->length_shared_secret);

    printf("Kyber space memory: \n");
    printf("Kyber Encapsulation key size: %ld\n",kyber->length_public_key);
    printf("Kyber Decapsulation key size:%ld\n",kyber->length_secret_key);
    printf("Kyber Ciphertext size: %ld\n",kyber->length_ciphertext);

    double total_kyber_keygen = 0, total_kyber_enc = 0, total_kyber_dec = 0;

    for (int i = 0; i < N_RUNS; i++) {
        // KeyGen
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_KEM_keypair(kyber, pk_kyber, sk_kyber);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total_kyber_keygen += time_diff_ms(t1, t2);

        // Encapsulation
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_KEM_encaps(kyber, ct_kyber, ss_enc_kyber, pk_kyber);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total_kyber_enc += time_diff_ms(t1, t2);

        // Decapsulation
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_KEM_decaps(kyber, ss_dec_kyber, ct_kyber, sk_kyber);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total_kyber_dec += time_diff_ms(t1, t2);
    }

    printf("Kyber metrics:\n");
    printf("Kyber Key Generation average time (%d runs): %.3f ms\n", N_RUNS, total_kyber_keygen / N_RUNS);
    printf("Kyber Encapsulation average time (%d runs): %.3f ms\n", N_RUNS, total_kyber_enc / N_RUNS);
    printf("Kyber Decapsulation average time (%d runs): %.3f ms\n", N_RUNS, total_kyber_dec / N_RUNS);



    // Cleanup Kyber
    OQS_KEM_free(kyber);
    free(pk_kyber);
    free(sk_kyber);
    free(ct_kyber);
    free(ss_enc_kyber);
    free(ss_dec_kyber);

    // --- RSA-2048 ---
    printf("\n-------------- RSA-2048 ---------------\n");

    // Initialize RSA
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4); // Public exponent 65537
    unsigned char plaintext_rsa[32]; // AES-256 Key = 32 Bytes
    unsigned char ciphertext_rsa[256]; // RSA ciphertext size is fixed: 256 bytes for a 2048-bit key (and does not depend on the plaintext's size)
    unsigned char decrypted_rsa[256];

    double total_rsa_keygen = 0, total_rsa_enc = 0, total_rsa_dec = 0;

    for (int i = 0; i < N_RUNS; i++) {
        // KeyGen
        RSA_free(rsa);
        rsa = RSA_new();
        clock_gettime(CLOCK_MONOTONIC, &t1);
        RSA_generate_key_ex(rsa, 2048, bn, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total_rsa_keygen += time_diff_ms(t1, t2);

        // Encryption (RSA-2048)
        RAND_bytes(plaintext_rsa, sizeof(plaintext_rsa));
        clock_gettime(CLOCK_MONOTONIC, &t1);
        RSA_public_encrypt(sizeof(plaintext_rsa), plaintext_rsa, ciphertext_rsa, rsa, RSA_PKCS1_OAEP_PADDING);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total_rsa_enc += time_diff_ms(t1, t2);

        // Decryption (RSA-2048)
        clock_gettime(CLOCK_MONOTONIC, &t1);
        RSA_private_decrypt(sizeof(ciphertext_rsa), ciphertext_rsa, decrypted_rsa, rsa, RSA_PKCS1_OAEP_PADDING);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total_rsa_dec += time_diff_ms(t1, t2);
    }

    printf("RSA metrics :\n");
    printf("RSA-2048 Key Generation average time (%d runs): %.3f ms\n", N_RUNS, total_rsa_keygen / N_RUNS);
    printf("RSA-2048 Encryption average time (%d runs): %.3f ms\n", N_RUNS, total_rsa_enc / N_RUNS);
    printf("RSA-2048 Decryption average time (%d runs): %.3f ms\n", N_RUNS, total_rsa_dec / N_RUNS);

    // Cleanup RSA
    RSA_free(rsa);
    BN_free(bn);

    return 0;
}
