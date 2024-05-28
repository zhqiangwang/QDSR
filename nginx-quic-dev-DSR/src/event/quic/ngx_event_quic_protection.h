
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_
#define _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_event_quic_transport.h>


#define NGX_QUIC_ENCRYPTION_LAST  ((ssl_encryption_application) + 1)


ngx_quic_keys_t *ngx_quic_keys_new(ngx_pool_t *pool);
ngx_int_t ngx_quic_keys_set_initial_secret(ngx_pool_t *pool,
    ngx_quic_keys_t *keys, ngx_str_t *secret, uint32_t version);
int ngx_quic_keys_set_encryption_secret(ngx_pool_t *pool, ngx_uint_t is_write,
    ngx_quic_keys_t *keys, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
ngx_uint_t ngx_quic_keys_available(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void ngx_quic_keys_discard(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void ngx_quic_keys_switch(ngx_connection_t *c, ngx_quic_keys_t *keys);
ngx_int_t ngx_quic_keys_update(ngx_connection_t *c, ngx_quic_keys_t *keys);
ngx_int_t ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_str_t *res);
ngx_int_t ngx_quic_decrypt(ngx_quic_header_t *pkt, uint64_t *largest_pn);



/* RFC 5116, 5.1 and RFC 8439, 2.3 for all supported ciphers */
#define NGX_QUIC_IV_LEN               12
/* RFC 9001, 5.4.1.  Header Protection Application: 5-byte mask */
#define NGX_QUIC_HP_LEN               5

#define NGX_QUIC_AES_128_KEY_LEN      16

#define NGX_AES_128_GCM_SHA256        0x1301
#define NGX_AES_256_GCM_SHA384        0x1302
#define NGX_CHACHA20_POLY1305_SHA256  0x1303


#ifdef OPENSSL_IS_BORINGSSL
#define ngx_quic_cipher_t             EVP_AEAD
#else
#define ngx_quic_cipher_t             EVP_CIPHER
#endif


typedef struct {
    const ngx_quic_cipher_t  *c;
    const EVP_CIPHER         *hp;
    const EVP_MD             *d;
} ngx_quic_ciphers_t;


typedef struct ngx_quic_secret_s {
    ngx_str_t                 secret;
    ngx_str_t                 key;
    ngx_str_t                 iv;
    ngx_str_t                 hp;
} ngx_quic_secret_t;


typedef struct {
    ngx_quic_secret_t         client;
    ngx_quic_secret_t         server;
} ngx_quic_secrets_t;


struct ngx_quic_keys_s {
    ngx_quic_secrets_t        secrets[NGX_QUIC_ENCRYPTION_LAST];
    ngx_quic_secrets_t        next_key;
    ngx_uint_t                cipher;
};


#endif /* _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_ */
