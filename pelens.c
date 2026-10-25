#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/* ========================================================================= */
/* MACROS & BOUNDS CHECKING                                                  */
/* ========================================================================= */

#define INBOUNDS(ptr, base, fileSize) \
    ((const BYTE*)(ptr) >= (const BYTE*)(base) && (const BYTE*)(ptr) < (const BYTE*)(base) + (fileSize))

#define INBOUNDS_SPAN(ptr, size, base, fileSize) \
    ((const BYTE*)(ptr) >= (const BYTE*)(base) && \
     (size) <= (fileSize) && \
     (const BYTE*)(ptr) + (size) <= (const BYTE*)(base) + (fileSize))

/* ========================================================================= */
/* MD5 HASH IMPLEMENTATION (RFC 1321) FOR IMPHASH                            */
/* ========================================================================= */

typedef struct {
    DWORD state[4];
    DWORD count[2];
    BYTE buffer[64];
} MD5_CTX;

#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

#define MD5_ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define MD5_FF(a, b, c, d, x, s, ac) { \
    (a) += MD5_F((b), (c), (d)) + (x) + (DWORD)(ac); \
    (a) = MD5_ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define MD5_GG(a, b, c, d, x, s, ac) { \
    (a) += MD5_G((b), (c), (d)) + (x) + (DWORD)(ac); \
    (a) = MD5_ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define MD5_HH(a, b, c, d, x, s, ac) { \
    (a) += MD5_H((b), (c), (d)) + (x) + (DWORD)(ac); \
    (a) = MD5_ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define MD5_II(a, b, c, d, x, s, ac) { \
    (a) += MD5_I((b), (c), (d)) + (x) + (DWORD)(ac); \
    (a) = MD5_ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

static void MD5Transform(DWORD state[4], const BYTE block[64]) {
    DWORD a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    for (int i = 0, j = 0; j < 64; i++, j += 4) {
        x[i] = ((DWORD)block[j]) | (((DWORD)block[j + 1]) << 8) |
               (((DWORD)block[j + 2]) << 16) | (((DWORD)block[j + 3]) << 24);
    }

    /* Round 1 */
    MD5_FF(a, b, c, d, x[ 0],  7, 0xd76aa478);
    MD5_FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    MD5_FF(c, d, a, b, x[ 2], 17, 0x242070db);
    MD5_FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    MD5_FF(a, b, c, d, x[ 4],  7, 0xf57c0faf);
    MD5_FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
    MD5_FF(c, d, a, b, x[ 6], 17, 0xa8304613);
    MD5_FF(b, c, d, a, x[ 7], 22, 0xfd469501);
    MD5_FF(a, b, c, d, x[ 8],  7, 0x698098d8);
    MD5_FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    MD5_FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    MD5_FF(b, c, d, a, x[11], 22, 0x895cd7be);
    MD5_FF(a, b, c, d, x[12],  7, 0x6b901122);
    MD5_FF(d, a, b, c, x[13], 12, 0xfd987193);
    MD5_FF(c, d, a, b, x[14], 17, 0xa679438e);
    MD5_FF(b, c, d, a, x[15], 22, 0x49b40821);

    /* Round 2 */
    MD5_GG(a, b, c, d, x[ 1],  5, 0xf61e2562);
    MD5_GG(d, a, b, c, x[ 6],  9, 0xc040b340);
    MD5_GG(c, d, a, b, x[11], 14, 0x265e5a51);
    MD5_GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    MD5_GG(a, b, c, d, x[ 5],  5, 0xd62f105d);
    MD5_GG(d, a, b, c, x[10],  9, 0x02441453);
    MD5_GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    MD5_GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    MD5_GG(a, b, c, d, x[ 9],  5, 0x21e1cde6);
    MD5_GG(d, a, b, c, x[14],  9, 0xc33707d6);
    MD5_GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);
    MD5_GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
    MD5_GG(a, b, c, d, x[13],  5, 0xa9e3e905);
    MD5_GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
    MD5_GG(c, d, a, b, x[ 7], 14, 0x676f02d9);
    MD5_GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    /* Round 3 */
    MD5_HH(a, b, c, d, x[ 5],  4, 0xfffa3942);
    MD5_HH(d, a, b, c, x[ 8], 11, 0x8771f681);
    MD5_HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    MD5_HH(b, c, d, a, x[14], 23, 0xfde5380c);
    MD5_HH(a, b, c, d, x[ 1],  4, 0xa4beea44);
    MD5_HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    MD5_HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
    MD5_HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    MD5_HH(a, b, c, d, x[13],  4, 0x289b7ec6);
    MD5_HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    MD5_HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);
    MD5_HH(b, c, d, a, x[ 6], 23, 0x04881d05);
    MD5_HH(a, b, c, d, x[ 9],  4, 0xd9d4d039);
    MD5_HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    MD5_HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    MD5_HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

    /* Round 4 */
    MD5_II(a, b, c, d, x[ 0],  6, 0xf4292244);
    MD5_II(d, a, b, c, x[ 7], 10, 0x432aff97);
    MD5_II(c, d, a, b, x[14], 15, 0xab9423a7);
    MD5_II(b, c, d, a, x[ 5], 21, 0xfc93a039);
    MD5_II(a, b, c, d, x[12],  6, 0x655b59c3);
    MD5_II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    MD5_II(c, d, a, b, x[10], 15, 0xffeff47d);
    MD5_II(b, c, d, a, x[ 1], 21, 0x85845dd1);
    MD5_II(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
    MD5_II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    MD5_II(c, d, a, b, x[ 6], 15, 0xa3014314);
    MD5_II(b, c, d, a, x[13], 21, 0x4e0811a1);
    MD5_II(a, b, c, d, x[ 4],  6, 0xf7537e82);
    MD5_II(d, a, b, c, x[11], 10, 0xbd3af235);
    MD5_II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
    MD5_II(b, c, d, a, x[ 9], 21, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void MD5Init(MD5_CTX* context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

static void MD5Update(MD5_CTX* context, const BYTE* input, DWORD inputLen) {
    DWORD i, index, partLen;
    index = (context->count[0] >> 3) & 0x3F;
    if ((context->count[0] += (inputLen << 3)) < (inputLen << 3)) {
        context->count[1]++;
    }
    context->count[1] += (inputLen >> 29);
    partLen = 64 - index;
    if (inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        MD5Transform(context->state, context->buffer);
        for (i = partLen; i + 63 < inputLen; i += 64) {
            MD5Transform(context->state, &input[i]);
        }
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

static void MD5Final(BYTE digest[16], MD5_CTX* context) {
    static const BYTE PADDING[64] = { 0x80, 0 };
    BYTE bits[8];
    DWORD index, padLen;
    for (int i = 0; i < 4; i++) {
        bits[i]     = (BYTE)((context->count[0] >> (i * 8)) & 0xFF);
        bits[i + 4] = (BYTE)((context->count[1] >> (i * 8)) & 0xFF);
    }
    index = (context->count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, PADDING, padLen);
    MD5Update(context, bits, 8);
    for (int i = 0; i < 4; i++) {
        digest[i * 4]     = (BYTE)(context->state[i] & 0xFF);
        digest[i * 4 + 1] = (BYTE)((context->state[i] >> 8) & 0xFF);
        digest[i * 4 + 2] = (BYTE)((context->state[i] >> 16) & 0xFF);
        digest[i * 4 + 3] = (BYTE)((context->state[i] >> 24) & 0xFF);
    }
}

/* ========================================================================= */
/* STRING & JSON HELPERS                                                     */
/* ========================================================================= */

void JsonEscape(const char* src, char* dst, size_t dstLen) {
    if (!src || !dst || dstLen == 0) return;
    size_t di = 0;
    for (size_t si = 0; src[si] != '\0' && di + 1 < dstLen; si++) {
        unsigned char c = (unsigned char)src[si];
        if (c == '"') {
            if (di + 2 >= dstLen) break;
            dst[di++] = '\\';
            dst[di++] = '"';
        } else if (c == '\\') {
            if (di + 2 >= dstLen) break;
            dst[di++] = '\\';
            dst[di++] = '\\';
        } else if (c == '\b') {
            if (di + 2 >= dstLen) break;
            dst[di++] = '\\';
            dst[di++] = 'b';
        } else if (c == '\f') {
            if (di + 2 >= dstLen) break;
            dst[di++] = '\\';
            dst[di++] = 'f';
        } else if (c == '\n') {
            if (di + 2 >= dstLen) break;
            dst[di++] = '\\';
            dst[di++] = 'n';
        } else if (c == '\r') {
            if (di + 2 >= dstLen) break;
            dst[di++] = '\\';
            dst[di++] = 'r';
        } else if (c == '\t') {
            if (di + 2 >= dstLen) break;
            dst[di++] = '\\';
            dst[di++] = 't';
        } else if (c < 0x20) {
            if (di + 6 >= dstLen) break;
            int written = snprintf(&dst[di], dstLen - di, "\\u%04x", (unsigned int)c);
            if (written > 0) di += (size_t)written;
        } else {
            dst[di++] = (char)c;
        }
    }
    dst[di] = '\0';
}

void CleanDllName(const char* dllName, char* outName, size_t outSize) {
    if (!dllName || !outName || outSize == 0) return;
    size_t len = strlen(dllName);
    if (len >= outSize) len = outSize - 1;
    for (size_t i = 0; i < len; i++) {
        outName[i] = (char)tolower((unsigned char)dllName[i]);
    }
    outName[len] = '\0';

    char* dot = strrchr(outName, '.');
    if (dot != NULL) {
        if (_stricmp(dot, ".dll") == 0 || _stricmp(dot, ".sys") == 0 ||
            _stricmp(dot, ".ocx") == 0 || _stricmp(dot, ".drv") == 0 ||
            _stricmp(dot, ".exe") == 0) {
            *dot = '\0';
        }
    }
}

/* ========================================================================= */
/* SHA-256 HASH VIA WINDOWS CNG (bcrypt.h)                                   */
/* ========================================================================= */

BOOL ComputeSHA256(const BYTE* data, DWORD size, char outHex[65]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    BYTE hash[32];

    outHex[0] = '\0';
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, size, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    status = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return FALSE;

    for (int i = 0; i < 32; i++) {
        sprintf(&outHex[i * 2], "%02x", hash[i]);
    }
    outHex[64] = '\0';
    return TRUE;
}

/* ========================================================================= */
/* ENTROPY & RVA CALCULATIONS                                                */
/* ========================================================================= */

double CalculateEntropy(const BYTE* pData, DWORD dataSize) {
    if (dataSize == 0 || pData == NULL) return 0.0;

    DWORD byteCounts[256] = { 0 };
    for (DWORD i = 0; i < dataSize; i++) {
        byteCounts[pData[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = (double)byteCounts[i] / dataSize;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER pSections, WORD numSections, DWORD fileSize) {
    if (!pSections || numSections == 0) return (DWORD)-1;

    for (WORD i = 0; i < numSections; i++) {
        DWORD vecAddr = pSections[i].VirtualAddress;
        DWORD vecSize = pSections[i].Misc.VirtualSize;
        if (vecSize == 0) {
            vecSize = pSections[i].SizeOfRawData;
        }
        if (rva >= vecAddr && rva < vecAddr + vecSize) {
            DWORD diff = rva - vecAddr;
            if (diff < pSections[i].SizeOfRawData) {
                DWORD fileOffset = pSections[i].PointerToRawData + diff;
                if (fileOffset < fileSize) {
                    return fileOffset;
                }
            }
            return (DWORD)-1;
        }
    }
    return (DWORD)-1;
}

BOOL ReadSafeString(const BYTE* fileBase, DWORD fileSize, DWORD offset, char* outBuf, size_t outBufSize) {
    if (offset >= fileSize || outBufSize == 0) return FALSE;
    const char* src = (const char*)(fileBase + offset);
    size_t maxLen = (size_t)(fileSize - offset);
    size_t len = 0;
    while (len < maxLen && src[len] != '\0') {
        len++;
    }
    if (len >= maxLen) return FALSE;
    if (len >= outBufSize) {
        len = outBufSize - 1;
    }
    memcpy(outBuf, src, len);
    outBuf[len] = '\0';
    return TRUE;
}

void GetTimeStampStringUTC(DWORD timeStamp, char* outBuffer, size_t bufSize) {
    time_t rawTime = (time_t)timeStamp;
    struct tm timeInfo;
    if (gmtime_s(&timeInfo, &rawTime) == 0) {
        strftime(outBuffer, bufSize, "%Y-%m-%d %H:%M:%S UTC", &timeInfo);
    } else {
        snprintf(outBuffer, bufSize, "0x%08lX UTC", timeStamp);
    }
}

/* ========================================================================= */
/* API CATEGORIZATION                                                        */
/* ========================================================================= */

const char* GetApiCategory(const char* apiName) {
    if (!apiName) return NULL;

    /* INJECTION */
    if (strcmp(apiName, "VirtualAlloc") == 0 ||
        strcmp(apiName, "VirtualAllocEx") == 0 ||
        strcmp(apiName, "WriteProcessMemory") == 0 ||
        strcmp(apiName, "CreateRemoteThread") == 0 ||
        strcmp(apiName, "CreateRemoteThreadEx") == 0 ||
        strcmp(apiName, "NtUnmapViewOfSection") == 0 ||
        strcmp(apiName, "ZwUnmapViewOfSection") == 0) {
        return "INJECTION";
    }

    /* ANTI_DEBUG */
    if (strcmp(apiName, "IsDebuggerPresent") == 0 ||
        strcmp(apiName, "CheckRemoteDebuggerPresent") == 0 ||
        strcmp(apiName, "NtQueryInformationProcess") == 0 ||
        strcmp(apiName, "ZwQueryInformationProcess") == 0) {
        return "ANTI_DEBUG";
    }

    /* DYN_RESOLVE */
    if (strcmp(apiName, "GetProcAddress") == 0 ||
        strcmp(apiName, "LoadLibraryA") == 0 ||
        strcmp(apiName, "LoadLibraryW") == 0 ||
        strcmp(apiName, "LoadLibraryExA") == 0 ||
        strcmp(apiName, "LoadLibraryExW") == 0) {
        return "DYN_RESOLVE";
    }

    /* PERSISTENCE */
    if (strstr(apiName, "RegSetValueEx") != NULL ||
        strcmp(apiName, "CreateServiceA") == 0 ||
        strcmp(apiName, "CreateServiceW") == 0 ||
        strcmp(apiName, "SchtasksW") == 0 ||
        strcmp(apiName, "SchtasksA") == 0) {
        return "PERSISTENCE";
    }

    /* NETWORK */
    if (strcmp(apiName, "InternetOpenA") == 0 ||
        strcmp(apiName, "InternetOpenW") == 0 ||
        strcmp(apiName, "InternetConnectA") == 0 ||
        strcmp(apiName, "InternetConnectW") == 0 ||
        strcmp(apiName, "HttpSendRequestA") == 0 ||
        strcmp(apiName, "HttpSendRequestW") == 0 ||
        strcmp(apiName, "WSAStartup") == 0 ||
        strcmp(apiName, "connect") == 0 ||
        strcmp(apiName, "send") == 0 ||
        strcmp(apiName, "recv") == 0) {
        return "NETWORK";
    }

    /* CRYPTO */
    if (strcmp(apiName, "CryptEncrypt") == 0 ||
        strcmp(apiName, "CryptDecrypt") == 0 ||
        strcmp(apiName, "CryptGenKey") == 0) {
        return "CRYPTO";
    }

    return NULL;
}

/* ========================================================================= */
/* IMPHASH LIST STRUCTURE                                                    */
/* ========================================================================= */

typedef struct {
    char** items;
    size_t count;
    size_t capacity;
} ImphashList;

static void ImphashListInit(ImphashList* list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void ImphashListAdd(ImphashList* list, const char* str) {
    if (list->count >= list->capacity) {
        size_t newCap = (list->capacity == 0) ? 64 : list->capacity * 2;
        char** newItems = (char**)realloc(list->items, newCap * sizeof(char*));
        if (!newItems) return;
        list->items = newItems;
        list->capacity = newCap;
    }
    list->items[list->count] = _strdup(str);
    if (list->items[list->count]) {
        list->count++;
    }
}

static void ImphashListFree(ImphashList* list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int CompareStrings(const void* a, const void* b) {
    const char* strA = *(const char* const*)a;
    const char* strB = *(const char* const*)b;
    return strcmp(strA, strB);
}

typedef struct {
    char name[256];
    const char* category;
} FunctionRecord;

/* ========================================================================= */
/* MAIN ENTRY POINT (wmain)                                                  */
/* ========================================================================= */

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) {
        wprintf(L"Usage: %s <target_pe_file> [-o output.json]\n", argv[0]);
        return 1;
    }

    const wchar_t* targetPathW = NULL;
    const wchar_t* outputPathW = L"pelens_report.json";

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"-o") == 0 && i + 1 < argc) {
            outputPathW = argv[++i];
        } else if (targetPathW == NULL && argv[i][0] != L'-') {
            targetPathW = argv[i];
        }
    }

    if (!targetPathW) {
        wprintf(L"[-] ERROR: No target binary file specified.\n");
        wprintf(L"Usage: %s <target_pe_file> [-o output.json]\n", argv[0]);
        return 1;
    }

    char targetPathUtf8[MAX_PATH * 4] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, targetPathW, -1, targetPathUtf8, sizeof(targetPathUtf8), NULL, NULL);

    /* Extract basename for privacy */
    const char* baseName = targetPathUtf8;
    for (const char* p = targetPathUtf8; *p; p++) {
        if (*p == '/' || *p == '\\') {
            baseName = p + 1;
        }
    }

    HANDLE hFile = CreateFileW(targetPathW, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] ERROR: Failed to open target binary file.\n");
        return 1;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart < (LONGLONG)sizeof(IMAGE_DOS_HEADER) || liSize.HighPart != 0) {
        printf("[-] ERROR: Invalid file size or file too small to be a PE binary.\n");
        CloseHandle(hFile);
        return 1;
    }
    DWORD fileSize = (DWORD)liSize.LowPart;

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        printf("[-] ERROR: CreateFileMapping failed (Error %lu).\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (fileBase == NULL) {
        printf("[-] ERROR: MapViewOfFile failed (Error %lu).\n", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    /* Validate DOS header */
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] ERROR: Invalid PE format (MZ signature missing).\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    /* Validate e_lfanew */
    if (pDosHeader->e_lfanew <= (LONG)sizeof(IMAGE_DOS_HEADER) ||
        (DWORD)pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > fileSize) {
        printf("[-] ERROR: Corrupt PE header (e_lfanew out of bounds).\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    DWORD ntSigOffset = (DWORD)pDosHeader->e_lfanew;
    DWORD ntSignature = *(DWORD*)((BYTE*)fileBase + ntSigOffset);
    if (ntSignature != IMAGE_NT_SIGNATURE) {
        printf("[-] ERROR: Invalid PE format (PE signature missing).\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((BYTE*)fileBase + ntSigOffset + 4);
    if (pFileHeader->SizeOfOptionalHeader < sizeof(WORD)) {
        printf("[-] ERROR: Missing or invalid OptionalHeader.\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    DWORD optHdrOffset = ntSigOffset + 4 + sizeof(IMAGE_FILE_HEADER);
    if (optHdrOffset + pFileHeader->SizeOfOptionalHeader > fileSize) {
        printf("[-] ERROR: OptionalHeader extends beyond file size.\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    WORD optMagic = *(WORD*)((BYTE*)fileBase + optHdrOffset);
    BOOL is64Bit = FALSE;
    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is64Bit = TRUE;
    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        is64Bit = FALSE;
    } else {
        printf("[-] ERROR: Unsupported OptionalHeader magic: 0x%04X\n", optMagic);
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    /* Section headers bounds */
    DWORD sectionHeadersOffset = optHdrOffset + pFileHeader->SizeOfOptionalHeader;
    WORD numberOfSections = pFileHeader->NumberOfSections;
    if (sectionHeadersOffset + (DWORD)numberOfSections * sizeof(IMAGE_SECTION_HEADER) > fileSize) {
        printf("[-] ERROR: Section headers extend beyond file size.\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }
    PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((BYTE*)fileBase + sectionHeadersOffset);

    /* Architecture string */
    const char* archStr = "UNKNOWN";
    switch (pFileHeader->Machine) {
        case IMAGE_FILE_MACHINE_I386:  archStr = "I386"; break;
        case IMAGE_FILE_MACHINE_AMD64: archStr = "AMD64"; break;
        case IMAGE_FILE_MACHINE_ARM:   archStr = "ARM"; break;
        case IMAGE_FILE_MACHINE_ARM64: archStr = "ARM64"; break;
        case IMAGE_FILE_MACHINE_IA64:  archStr = "IA64"; break;
        default: archStr = "UNKNOWN"; break;
    }
    const char* peTypeStr = is64Bit ? "PE32+" : "PE32";

    /* Extract fields from OptionalHeader */
    DWORD entryPointRva = 0;
    WORD dllCharacteristics = 0;
    IMAGE_DATA_DIRECTORY importDir = { 0, 0 };

    if (is64Bit) {
        PIMAGE_OPTIONAL_HEADER64 pOpt64 = (PIMAGE_OPTIONAL_HEADER64)((BYTE*)fileBase + optHdrOffset);
        entryPointRva = pOpt64->AddressOfEntryPoint;
        dllCharacteristics = pOpt64->DllCharacteristics;
        if (pOpt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            importDir = pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
    } else {
        PIMAGE_OPTIONAL_HEADER32 pOpt32 = (PIMAGE_OPTIONAL_HEADER32)((BYTE*)fileBase + optHdrOffset);
        entryPointRva = pOpt32->AddressOfEntryPoint;
        dllCharacteristics = pOpt32->DllCharacteristics;
        if (pOpt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            importDir = pOpt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
    }

    BOOL hasAslr = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    BOOL hasDep  = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    BOOL hasCfg  = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;

    /* Entry Point Section */
    char epSectionName[16] = "UNKNOWN";
    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD vAddr = pSectionHeaders[i].VirtualAddress;
        DWORD vSize = pSectionHeaders[i].Misc.VirtualSize ? pSectionHeaders[i].Misc.VirtualSize : pSectionHeaders[i].SizeOfRawData;
        if (entryPointRva >= vAddr && entryPointRva < vAddr + vSize) {
            char secName[9] = { 0 };
            memcpy(secName, pSectionHeaders[i].Name, 8);
            strncpy(epSectionName, secName, sizeof(epSectionName) - 1);
            break;
        }
    }
    if (entryPointRva == 0) {
        strcpy(epSectionName, "NONE");
    }

    /* Overlay Detection */
    DWORD maxRawEnd = 0;
    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD end = pSectionHeaders[i].PointerToRawData + pSectionHeaders[i].SizeOfRawData;
        if (end > maxRawEnd) {
            maxRawEnd = end;
        }
    }
    DWORD overlayBytes = (fileSize > maxRawEnd) ? (fileSize - maxRawEnd) : 0;

    /* Compute SHA-256 */
    char sha256Hex[65] = { 0 };
    ComputeSHA256((const BYTE*)fileBase, fileSize, sha256Hex);

    /* Compute Imphash (Pass 1) */
    char imphashHex[33] = "d41d8cd98f00b204e9800998ecf8427e";
    ImphashList imphashList;
    ImphashListInit(&imphashList);

    if (importDir.VirtualAddress != 0) {
        DWORD impOff = RvaToOffset(importDir.VirtualAddress, pSectionHeaders, numberOfSections, fileSize);
        if (impOff != (DWORD)-1 && impOff < fileSize) {
            PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)fileBase + impOff);
            while (INBOUNDS_SPAN(pImp, sizeof(IMAGE_IMPORT_DESCRIPTOR), fileBase, fileSize)) {
                if (pImp->Characteristics == 0 && pImp->FirstThunk == 0) break;
                if (pImp->Name != 0) {
                    DWORD nOff = RvaToOffset(pImp->Name, pSectionHeaders, numberOfSections, fileSize);
                    char rawDll[260] = { 0 };
                    char cleanDll[260] = { 0 };
                    if (nOff != (DWORD)-1 && ReadSafeString((const BYTE*)fileBase, fileSize, nOff, rawDll, sizeof(rawDll))) {
                        CleanDllName(rawDll, cleanDll, sizeof(cleanDll));
                        DWORD thunkRva = pImp->OriginalFirstThunk ? pImp->OriginalFirstThunk : pImp->FirstThunk;
                        DWORD thunkOff = RvaToOffset(thunkRva, pSectionHeaders, numberOfSections, fileSize);
                        if (thunkOff != (DWORD)-1 && thunkOff < fileSize) {
                            if (is64Bit) {
                                PIMAGE_THUNK_DATA64 pTh = (PIMAGE_THUNK_DATA64)((BYTE*)fileBase + thunkOff);
                                while (INBOUNDS_SPAN(pTh, sizeof(IMAGE_THUNK_DATA64), fileBase, fileSize) && pTh->u1.AddressOfData != 0) {
                                    if (pTh->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                                        char pairBuf[300];
                                        snprintf(pairBuf, sizeof(pairBuf), "%s.ord%lu", cleanDll, (DWORD)(pTh->u1.Ordinal & 0xFFFF));
                                        ImphashListAdd(&imphashList, pairBuf);
                                    } else {
                                        DWORD fnRva = (DWORD)(pTh->u1.AddressOfData & 0xFFFFFFFF);
                                        DWORD fnOff = RvaToOffset(fnRva, pSectionHeaders, numberOfSections, fileSize);
                                        if (fnOff != (DWORD)-1 && fnOff + sizeof(WORD) < fileSize) {
                                            char fnName[260] = { 0 };
                                            if (ReadSafeString((const BYTE*)fileBase, fileSize, fnOff + sizeof(WORD), fnName, sizeof(fnName))) {
                                                char fnLower[260] = { 0 };
                                                for (size_t k = 0; fnName[k]; k++) {
                                                    fnLower[k] = (char)tolower((unsigned char)fnName[k]);
                                                }
                                                char pairBuf[520];
                                                snprintf(pairBuf, sizeof(pairBuf), "%s.%s", cleanDll, fnLower);
                                                ImphashListAdd(&imphashList, pairBuf);
                                            }
                                        }
                                    }
                                    pTh++;
                                }
                            } else {
                                PIMAGE_THUNK_DATA32 pTh = (PIMAGE_THUNK_DATA32)((BYTE*)fileBase + thunkOff);
                                while (INBOUNDS_SPAN(pTh, sizeof(IMAGE_THUNK_DATA32), fileBase, fileSize) && pTh->u1.AddressOfData != 0) {
                                    if (pTh->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                                        char pairBuf[300];
                                        snprintf(pairBuf, sizeof(pairBuf), "%s.ord%lu", cleanDll, (DWORD)(pTh->u1.Ordinal & 0xFFFF));
                                        ImphashListAdd(&imphashList, pairBuf);
                                    } else {
                                        DWORD fnRva = pTh->u1.AddressOfData;
                                        DWORD fnOff = RvaToOffset(fnRva, pSectionHeaders, numberOfSections, fileSize);
                                        if (fnOff != (DWORD)-1 && fnOff + sizeof(WORD) < fileSize) {
                                            char fnName[260] = { 0 };
                                            if (ReadSafeString((const BYTE*)fileBase, fileSize, fnOff + sizeof(WORD), fnName, sizeof(fnName))) {
                                                char fnLower[260] = { 0 };
                                                for (size_t k = 0; fnName[k]; k++) {
                                                    fnLower[k] = (char)tolower((unsigned char)fnName[k]);
                                                }
                                                char pairBuf[520];
                                                snprintf(pairBuf, sizeof(pairBuf), "%s.%s", cleanDll, fnLower);
                                                ImphashListAdd(&imphashList, pairBuf);
                                            }
                                        }
                                    }
                                    pTh++;
                                }
                            }
                        }
                    }
                }
                pImp++;
            }
        }
    }

    if (imphashList.count > 0) {
        qsort(imphashList.items, imphashList.count, sizeof(char*), CompareStrings);
        size_t totalLen = 0;
        for (size_t i = 0; i < imphashList.count; i++) {
            totalLen += strlen(imphashList.items[i]) + 1;
        }
        char* joined = (char*)malloc(totalLen + 1);
        if (joined) {
            joined[0] = '\0';
            for (size_t i = 0; i < imphashList.count; i++) {
                if (i > 0) strcat(joined, ",");
                strcat(joined, imphashList.items[i]);
            }
            MD5_CTX md5;
            BYTE digest[16];
            MD5Init(&md5);
            MD5Update(&md5, (const BYTE*)joined, (DWORD)strlen(joined));
            MD5Final(digest, &md5);
            for (int i = 0; i < 16; i++) {
                sprintf(&imphashHex[i * 2], "%02x", digest[i]);
            }
            imphashHex[32] = '\0';
            free(joined);
        }
    }
    ImphashListFree(&imphashList);

    /* Open JSON output file */
    FILE* jsonFile = _wfopen(outputPathW, L"w");
    if (!jsonFile) {
        printf("[-] WARNING: Could not open JSON report for writing.\n");
    }

    char timeStr[64];
    GetTimeStampStringUTC(pFileHeader->TimeDateStamp, timeStr, sizeof(timeStr));

    /* Console banner */
    printf("=======================================================\n");
    printf("  PELens — PE Static Analysis Tool\n");
    printf("  Fast. Portable. Forensic-Grade.\n");
    printf("=======================================================\n");
    printf("[*] Target Binary                   : %s\n", baseName);
    printf("[+] SHA-256                         : %s\n", sha256Hex);
    printf("[+] Architecture                    : %s (%s)\n", archStr, peTypeStr);
    printf("[+] Compile Timestamp               : %s\n", timeStr);
    printf("[+] Total Sections                  : %u\n", numberOfSections);
    printf("[+] File Size                       : %lu bytes\n", fileSize);
    printf("[+] Entry Point RVA                 : 0x%08lX (%s)\n", entryPointRva, epSectionName);
    if (strcmp(epSectionName, ".text") != 0 && strcmp(epSectionName, "NONE") != 0) {
        printf("    [!] WARNING: Entry point is NOT in .text section!\n");
    }
    printf("[+] Imphash                         : %s\n", imphashHex);
    printf("[+] Security Mitigations           : ASLR: %s | DEP: %s | CFG: %s\n",
        hasAslr ? "YES" : "NO", hasDep ? "YES" : "NO", hasCfg ? "YES" : "NO");
    if (overlayBytes > 0) {
        printf("[+] Overlay Detected                : %lu bytes at EOF\n", overlayBytes);
    } else {
        printf("[+] Overlay Detected                : None (0 bytes)\n");
    }
    printf("\n");

    /* JSON header */
    if (jsonFile) {
        char escBaseName[512];
        JsonEscape(baseName, escBaseName, sizeof(escBaseName));
        fprintf(jsonFile, "{\n");
        fprintf(jsonFile, "  \"tool\": \"pelens\",\n");
        fprintf(jsonFile, "  \"target_file\": \"%s\",\n", escBaseName);
        fprintf(jsonFile, "  \"sha256\": \"%s\",\n", sha256Hex);
        fprintf(jsonFile, "  \"file_size\": %lu,\n", fileSize);
        fprintf(jsonFile, "  \"arch\": \"%s\",\n", archStr);
        fprintf(jsonFile, "  \"pe_type\": \"%s\",\n", peTypeStr);
        fprintf(jsonFile, "  \"compile_date\": \"%s\",\n", timeStr);
        fprintf(jsonFile, "  \"entry_point_rva\": %lu,\n", entryPointRva);
        fprintf(jsonFile, "  \"entry_point_section\": \"%s\",\n", epSectionName);
        fprintf(jsonFile, "  \"overlay_bytes\": %lu,\n", overlayBytes);
        fprintf(jsonFile, "  \"dll_characteristics\": {\n");
        fprintf(jsonFile, "    \"aslr\": %s,\n", hasAslr ? "true" : "false");
        fprintf(jsonFile, "    \"dep\": %s,\n", hasDep ? "true" : "false");
        fprintf(jsonFile, "    \"cfg\": %s\n", hasCfg ? "true" : "false");
        fprintf(jsonFile, "  },\n");
        fprintf(jsonFile, "  \"imphash\": \"%s\",\n", imphashHex);
        fprintf(jsonFile, "  \"sections_count\": %u,\n", numberOfSections);
        fprintf(jsonFile, "  \"sections\": [\n");
    }

    /* Print Section Table */
    printf("+---------------------------------------------------------------------------+\n");
    printf("| NAME     | VIRT SIZE  | RAW SIZE   | ENTROPY  | PERMS  | FLAGS            |\n");
    printf("+---------------------------------------------------------------------------+\n");

    for (WORD i = 0; i < numberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, pSectionHeaders[i].Name, 8);

        DWORD virtualSize = pSectionHeaders[i].Misc.VirtualSize;
        DWORD rawSize = pSectionHeaders[i].SizeOfRawData;
        DWORD rawOffset = pSectionHeaders[i].PointerToRawData;
        DWORD characteristics = pSectionHeaders[i].Characteristics;

        double entropy = 0.0;
        if (rawOffset < fileSize && rawSize > 0) {
            DWORD validSize = rawSize;
            if (rawOffset + validSize > fileSize) {
                validSize = fileSize - rawOffset;
            }
            const BYTE* pSectionData = (const BYTE*)fileBase + rawOffset;
            entropy = CalculateEntropy(pSectionData, validSize);
        }

        BOOL isRead    = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL isWrite   = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        BOOL isExecute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL isRWX     = isWrite && isExecute;
        BOOL isBss     = (_stricmp(sectionName, ".bss") == 0);
        BOOL isPacked  = (entropy > 7.1 || (rawSize == 0 && virtualSize > 0 && !isBss));

        char flagsStr[32] = "OK";
        if (isRWX && isPacked) strcpy(flagsStr, "[!] RWX & SUSP");
        else if (isRWX) strcpy(flagsStr, "[!] RWX DETECTED");
        else if (isPacked) strcpy(flagsStr, "[!] SUSP ENTROPY");

        printf("| %-8s | %-10lu | %-10lu | %-8.4f | %s%s%s    | %-16s |\n",
            sectionName, virtualSize, rawSize, entropy,
            isRead ? "R" : "-", isWrite ? "W" : "-", isExecute ? "X" : "-", flagsStr);

        if (jsonFile) {
            char escSecName[64];
            JsonEscape(sectionName, escSecName, sizeof(escSecName));
            fprintf(jsonFile, "    {\n");
            fprintf(jsonFile, "      \"name\": \"%s\",\n", escSecName);
            fprintf(jsonFile, "      \"virtual_size\": %lu,\n", virtualSize);
            fprintf(jsonFile, "      \"raw_size\": %lu,\n", rawSize);
            fprintf(jsonFile, "      \"entropy\": %.4f,\n", entropy);
            fprintf(jsonFile, "      \"permissions\": \"%s%s%s\",\n", isRead ? "R" : "-", isWrite ? "W" : "-", isExecute ? "X" : "-");
            fprintf(jsonFile, "      \"is_rwx\": %s,\n", isRWX ? "true" : "false");
            fprintf(jsonFile, "      \"is_packed_suspicion\": %s\n", isPacked ? "true" : "false");
            fprintf(jsonFile, "    }%s\n", (i == numberOfSections - 1) ? "" : ",");
        }
    }
    printf("+---------------------------------------------------------------------------+\n");

    if (jsonFile) {
        fprintf(jsonFile, "  ],\n  \"imports\": [\n");
    }

    printf("\n--- [ IMPORT ADDRESS TABLE (IAT) SUMMARY ] ---\n");

    if (importDir.VirtualAddress != 0) {
        DWORD importOffset = RvaToOffset(importDir.VirtualAddress, pSectionHeaders, numberOfSections, fileSize);
        if (importOffset != (DWORD)-1 && importOffset < fileSize) {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)fileBase + importOffset);
            BOOL firstDll = TRUE;

            while (INBOUNDS_SPAN(pImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), fileBase, fileSize)) {
                if (pImportDesc->Characteristics == 0 && pImportDesc->FirstThunk == 0) {
                    break;
                }
                if (pImportDesc->Name == 0) {
                    pImportDesc++;
                    continue;
                }

                DWORD nameOffset = RvaToOffset(pImportDesc->Name, pSectionHeaders, numberOfSections, fileSize);
                char dllName[260] = "UNKNOWN";
                if (nameOffset != (DWORD)-1) {
                    ReadSafeString((const BYTE*)fileBase, fileSize, nameOffset, dllName, sizeof(dllName));
                }

                DWORD thunkRVA = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;
                DWORD thunkOffset = RvaToOffset(thunkRVA, pSectionHeaders, numberOfSections, fileSize);

                DWORD ordinalCount = 0;
                FunctionRecord* funcList = NULL;
                size_t funcCount = 0;
                size_t funcCap = 0;

                if (thunkOffset != (DWORD)-1 && thunkOffset < fileSize) {
                    if (is64Bit) {
                        PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)((BYTE*)fileBase + thunkOffset);
                        while (INBOUNDS_SPAN(pThunk, sizeof(IMAGE_THUNK_DATA64), fileBase, fileSize) && pThunk->u1.AddressOfData != 0) {
                            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                                ordinalCount++;
                            } else {
                                DWORD dataRva = (DWORD)(pThunk->u1.AddressOfData & 0xFFFFFFFF);
                                DWORD dataOffset = RvaToOffset(dataRva, pSectionHeaders, numberOfSections, fileSize);
                                if (dataOffset != (DWORD)-1 && dataOffset + sizeof(WORD) < fileSize) {
                                    char funcName[256] = { 0 };
                                    if (ReadSafeString((const BYTE*)fileBase, fileSize, dataOffset + sizeof(WORD), funcName, sizeof(funcName))) {
                                        if (funcCount >= funcCap) {
                                            size_t newC = (funcCap == 0) ? 32 : funcCap * 2;
                                            FunctionRecord* nRec = (FunctionRecord*)realloc(funcList, newC * sizeof(FunctionRecord));
                                            if (nRec) {
                                                funcList = nRec;
                                                funcCap = newC;
                                            }
                                        }
                                        if (funcCount < funcCap) {
                                            strncpy(funcList[funcCount].name, funcName, sizeof(funcList[funcCount].name) - 1);
                                            funcList[funcCount].name[sizeof(funcList[funcCount].name) - 1] = '\0';
                                            funcList[funcCount].category = GetApiCategory(funcName);
                                            funcCount++;
                                        }
                                    }
                                }
                            }
                            pThunk++;
                        }
                    } else {
                        PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)((BYTE*)fileBase + thunkOffset);
                        while (INBOUNDS_SPAN(pThunk, sizeof(IMAGE_THUNK_DATA32), fileBase, fileSize) && pThunk->u1.AddressOfData != 0) {
                            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                                ordinalCount++;
                            } else {
                                DWORD dataRva = pThunk->u1.AddressOfData;
                                DWORD dataOffset = RvaToOffset(dataRva, pSectionHeaders, numberOfSections, fileSize);
                                if (dataOffset != (DWORD)-1 && dataOffset + sizeof(WORD) < fileSize) {
                                    char funcName[256] = { 0 };
                                    if (ReadSafeString((const BYTE*)fileBase, fileSize, dataOffset + sizeof(WORD), funcName, sizeof(funcName))) {
                                        if (funcCount >= funcCap) {
                                            size_t newC = (funcCap == 0) ? 32 : funcCap * 2;
                                            FunctionRecord* nRec = (FunctionRecord*)realloc(funcList, newC * sizeof(FunctionRecord));
                                            if (nRec) {
                                                funcList = nRec;
                                                funcCap = newC;
                                            }
                                        }
                                        if (funcCount < funcCap) {
                                            strncpy(funcList[funcCount].name, funcName, sizeof(funcList[funcCount].name) - 1);
                                            funcList[funcCount].name[sizeof(funcList[funcCount].name) - 1] = '\0';
                                            funcList[funcCount].category = GetApiCategory(funcName);
                                            funcCount++;
                                        }
                                    }
                                }
                            }
                            pThunk++;
                        }
                    }
                }

                printf("\n[+] DLL: %s (Ordinals: %lu)\n", dllName, ordinalCount);
                for (size_t f = 0; f < funcCount && f < 5; f++) {
                    if (funcList[f].category) {
                        printf("    |-- %-30s [%s]\n", funcList[f].name, funcList[f].category);
                    } else {
                        printf("    |-- %-30s\n", funcList[f].name);
                    }
                }
                if (funcCount > 5) {
                    printf("    \\-- ... and %llu more functions.\n", (unsigned long long)(funcCount - 5));
                }

                if (jsonFile) {
                    char escDll[512];
                    JsonEscape(dllName, escDll, sizeof(escDll));
                    fprintf(jsonFile, "%s    {\n", firstDll ? "" : ",\n");
                    firstDll = FALSE;
                    fprintf(jsonFile, "      \"dll\": \"%s\",\n", escDll);
                    fprintf(jsonFile, "      \"ordinal_count\": %lu,\n", ordinalCount);
                    fprintf(jsonFile, "      \"functions\": [\n");
                    for (size_t f = 0; f < funcCount; f++) {
                        char escFuncName[512];
                        JsonEscape(funcList[f].name, escFuncName, sizeof(escFuncName));
                        if (funcList[f].category) {
                            fprintf(jsonFile, "        { \"name\": \"%s\", \"category\": \"%s\" }%s\n",
                                escFuncName, funcList[f].category, (f + 1 == funcCount) ? "" : ",");
                        } else {
                            fprintf(jsonFile, "        { \"name\": \"%s\", \"category\": null }%s\n",
                                escFuncName, (f + 1 == funcCount) ? "" : ",");
                        }
                    }
                    fprintf(jsonFile, "      ]\n    }");
                }

                if (funcList) {
                    free(funcList);
                }
                pImportDesc++;
            }
        }
    }

    if (jsonFile) {
        fprintf(jsonFile, "\n  ]\n}\n");
        fclose(jsonFile);
        char outUtf8[MAX_PATH * 4] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, outputPathW, -1, outUtf8, sizeof(outUtf8), NULL, NULL);
        printf("\n[+] Technical Analysis Complete. Output exported to: %s\n", outUtf8);
    }

    UnmapViewOfFile(fileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    printf("=======================================================\n");
    return 0;
}
