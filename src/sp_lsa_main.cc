#include "lsa_functions.h"
#include "lsa_ap_main.h"

#include <plog/Log.h>

extern "C"
NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters, PLSA_SECPKG_FUNCTION_TABLE FunctionTable) {
  PLOG(plog::debug) << "SpInitialize";
  return 0;
}

static NTSTATUS NTAPI SpShutDown() {
  PLOG(plog::debug) << "SpShutDown";
  return 0;
}

NTSTATUS NTAPI SpGetInfo(PSecPkgInfoW PackageInfo)
{
  PLOG(plog::debug) << "SpGetInfo";
  PackageInfo->Name = (SEC_WCHAR *)L"SSSPotless";
  PackageInfo->Comment = (SEC_WCHAR *)L"SSSPotless <o>";
  PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION | SECPKG_FLAG_LOGON;
  PackageInfo->wRPCID = SECPKG_ID_NONE;
  PackageInfo->cbMaxToken = 0;
  PackageInfo->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
  return 0;
}

static SECPKG_FUNCTION_TABLE sp_lsa_function_table[] =
    {
        {
            LsaApInitializePackage,
            LsaApLogonUser,
            NULL,
            LsaApLogonTerminated,
            LsaApCallPackageUntrusted,
            LsaApCallPackagePassthrough,
            LsaApLogonUserEx,
            LsaApLogonUserEx2,
            SpInitialize,
            SpShutDown,
            SpGetInfo,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        }
    };

extern "C" NTSTATUS NTAPI SpLsaModeInitialize(
    ULONG LsaVersion,
    PULONG PackageVersion,
    PSECPKG_FUNCTION_TABLE *ppTables,
    PULONG pcTables
) {
  *PackageVersion = SECPKG_INTERFACE_VERSION;
  *ppTables = sp_lsa_function_table;
  *pcTables = 1;
  return 0;
}

extern "C"
NTSTATUS NTAPI SpInstanceInit(
    _In_ ULONG Version,
    _In_ PSECPKG_DLL_FUNCTIONS FunctionTable,
    _Outptr_ PVOID * UserFunctions
) {
  PLOG(plog::debug) << "SpInstanceInit";
  return 0;
}
