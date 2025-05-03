/*
 * Copyright (c) 2025 m7.org
 * License: MTL-10 (see LICENSE.md)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define PORT 50000
#define TARGET "127.0.0.1"
#define PUBKEY_PATH "/etc/siglatch/keys/server_pub.pem"

int encrypt_with_pubkey(const char *pubkey_path, const unsigned char *msg, size_t msg_len,
                        unsigned char *out_buf, size_t *out_len) {
    FILE *fp = fopen(pubkey_path, "r");
    if (!fp) {
        perror("fopen pubkey");
        return 0;
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pubkey) {
        fprintf(stderr, "❌ Failed to read public key\n");
        return 0;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pubkey);
        fprintf(stderr, "❌ Failed to create PKEY context\n");
        return 0;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "❌ Encryption context init failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    size_t out_len_tmp = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len_tmp, msg, msg_len) <= 0) {
        fprintf(stderr, "❌ Encryption size estimation failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    if (EVP_PKEY_encrypt(ctx, out_buf, &out_len_tmp, msg, msg_len) <= 0) {
        fprintf(stderr, "❌ Encryption failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    *out_len = out_len_tmp;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <message>
", argv[0]);
        return 1;
    }

    int sock;
    struct sockaddr_in server;
    const char *message = argv[1];

    unsigned char encrypted[512];
    size_t encrypted_len = 0;

    if (!encrypt_with_pubkey(PUBKEY_PATH, (unsigned char *)message, strlen(message),
                             encrypted, &encrypted_len)) {
        fprintf(stderr, "❌ Encryption failed. Exiting.
");
        return 1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (inet_pton(AF_INET, TARGET, &server.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return 1;
    }

    ssize_t sent = sendto(sock, encrypted, encrypted_len, 0,
                          (struct sockaddr *)&server, sizeof(server));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    printf("📤 Sent encrypted knock to %s:%d\n", TARGET, PORT);
    close(sock);
    return 0;
}
