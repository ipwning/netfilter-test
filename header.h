#include <stdint.h>

typedef struct _ip_header {
    uint8_t ver:4;
    uint8_t h_len:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint8_t flags:3;
    uint16_t f_off:16;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip;
    uint32_t dip;
    uint8_t pay[0x800];
} ip_header;