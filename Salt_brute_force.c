
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t FNV1a(const char* key, size_t length, uint32_t salt) {
    uint32_t hash = 2166136261u ^ salt;
    for (size_t i = 0; i < length; i++) {
        hash ^= key[i];
        hash *= 16777619;
    }
    return hash;
}

int main() {

    uint32_t hash1 = 1708146889;
    uint32_t hash = NULL;
    uint32_t salt = 0; 
    const char* key = "example";



    while (hash != hash1) {
        salt++;
        hash = FNV1a(key, strlen(key), salt);
        getchar(); 
    }
    printf("The matching salt is %u and the hash is %u\n", salt, hash);
    getchar();

    return 0;
}
