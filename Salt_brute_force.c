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

void findMatchingSaltAndPrint(const char* key, uint32_t targetHash) {
    uint32_t hash = 0;
    uint32_t salt = 0;

    while (hash != targetHash) {
        salt++;
        hash = FNV1a(key, strlen(key), salt);
    }
    printf("The matching salt is %u and the hash is %u\n", salt, hash);
}

int main() {
    const char* key = "example";
    uint32_t hash1 = 1708146889;

    findMatchingSaltAndPrint(key, hash1);

    getchar();
    return 0;
}
