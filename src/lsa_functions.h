#ifndef LSA_FUNCTIONS_H_
#define LSA_FUNCTIONS_H_

#define SECURITY_WIN32
#include <Windows.h>
#include <Sspi.h>
#include <Ntsecapi.h>
#include <Ntsecpkg.h>

LSA_STRING *AllocateLsaStringLsa(
    LPCSTR szString
);
UNICODE_STRING *AllocateUnicodeStringLsa(
    LPCWSTR szString
);
LPVOID LsaAllocateHeap(
    ULONG size,
    LPBYTE * ppHeapBase,
    LPBYTE * ppHeapPtr
);

#endif //LSA_FUNCTIONS_H_
