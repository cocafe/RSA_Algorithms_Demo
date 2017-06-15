#ifndef SIMPLERSADIGEST_MISC_HELPER_H
#define SIMPLERSADIGEST_MISC_HELPER_H

#define ARRAY_SIZE(arr)                 (sizeof(arr) / sizeof((arr)[0]))

uint64_t urandom_read(void);
void memdump_byte(void *blk, size_t size, FILE *stream);

#endif //SIMPLERSADIGEST_MISC_HELPER_H
