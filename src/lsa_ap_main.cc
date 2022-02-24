#include "lsa_functions.h"
#include <winnt.h>

#include <plog/Log.h>

#include <LM.h>
#include <LsaLookup.h>

#define NTLKAP_NAME_A         "OEM_SSP_AP_V_1_0"
#define NTLKAP_NAME           TEXT("OEM_SSP_AP_V_1_0")

PLSA_DISPATCH_TABLE g_lsa_dispatch_table = nullptr;

extern "C" NTSTATUS NTAPI
LsaApInitializePackage(
    _In_
    ULONG AuthenticationPackageId,
    _In_
    PLSA_DISPATCH_TABLE LsaDispatchTable,
    _In_opt_
    PLSA_STRING Database,
    _In_opt_
    PLSA_STRING Confidentiality,
    _Out_
    PLSA_STRING *AuthenticationPackageName
) {
  NTSTATUS status = S_OK;

  PLOG(plog::debug) << "LsaApInitializePackage Called";

  UNREFERENCED_PARAMETER(AuthenticationPackageId);
  UNREFERENCED_PARAMETER(Database);
  UNREFERENCED_PARAMETER(Confidentiality);

  g_lsa_dispatch_table = LsaDispatchTable;

  *AuthenticationPackageName = AllocateLsaStringLsa(NTLKAP_NAME_A);

  if (NULL == *AuthenticationPackageName) {
    status = STATUS_NO_MEMORY;
    PLOG(plog::error) << "Can't allocate memory of authentication package name";
  }

  return status;
}

extern "C" NTSTATUS NTAPI
LsaApCallPackage(
    _In_
    PLSA_CLIENT_REQUEST ClientRequest,
    _In_reads_bytes_(SubmitBufferLength)
    PVOID ProtocolSubmitBuffer,
    _In_
    PVOID ClientBufferBase,
    _In_
    ULONG SubmitBufferLength,
    _Outptr_result_bytebuffer_(*ReturnBufferLength)
    PVOID *ProtocolReturnBuffer,
    _Out_
    PULONG ReturnBufferLength,
    _Out_
    PNTSTATUS ProtocolStatus
) {
  PLOG(plog::info) << "LsaApCallPackage";

  return E_NOTIMPL;
}

extern "C" VOID NTAPI
LsaApLogonTerminated(
    _In_
    PLUID LogonId
) {
  PLOG(plog::info) << "LsaApLogonTerminated";
}

extern "C" NTSTATUS NTAPI
LsaApLogonUser(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    PVOID AuthenticationInformation,
    PVOID ClientAuthenticationBase,
    ULONG AuthenticationInformationLength,
    PVOID *ProfileBuffer,
    PULONG ProfileBufferLength,
    PLUID LogonId,
    PNTSTATUS SubStatus,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation,
    PLSA_UNICODE_STRING *AccountName,
    PLSA_UNICODE_STRING *AuthenticatingAuthority
) {
  return E_NOTIMPL;
}

extern "C" NTSTATUS NTAPI
LsaApLogonUserEx(
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN SECURITY_LOGON_TYPE LogonType,
    IN PVOID ProtocolSubmitBuffer,
    IN PVOID ClientBufferBase,
    IN ULONG SubmitBufferSize,
    OUT PVOID *ProfileBuffer,
    OUT PULONG ProfileBufferSize,
    OUT PLUID LogonId,
    OUT PNTSTATUS SubStatus,
    OUT PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    OUT PVOID *TokenInformation,
    OUT PUNICODE_STRING *AccountName,
    OUT PUNICODE_STRING *AuthenticatingAuthority,
    OUT PUNICODE_STRING *MachineName
) {
  PLOG(plog::info) << "LsaApLogonUserEx";
  return E_NOTIMPL;
}

extern "C" NTSTATUS NTAPI
LsaApLogonUserEx2(
    _In_
    PLSA_CLIENT_REQUEST ClientRequest,
    _In_
    SECURITY_LOGON_TYPE LogonType,
    _In_reads_bytes_(SubmitBufferSize)
    PVOID ProtocolSubmitBuffer,
    _In_
    PVOID ClientBufferBase,
    _In_
    ULONG SubmitBufferSize,
    _Outptr_result_bytebuffer_(*ProfileBufferSize)
    PVOID *ProfileBuffer,
    _Out_
    PULONG ProfileBufferSize,
    _Out_
    PLUID LogonId,
    _Out_
    PNTSTATUS SubStatus,
    _Out_
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    _Outptr_
    PVOID *TokenInformation,
    _Out_
    PUNICODE_STRING *AccountName,
    _Out_
    PUNICODE_STRING *AuthenticatingAuthority,
    _Out_
    PUNICODE_STRING *MachineName,
    _Out_
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    _Outptr_
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials
) {
  PLOG(plog::info) << "LsaApLogonUserEx2";
  return E_NOTIMPL;
}

extern "C" NTSTATUS NTAPI
LsaApCallPackageUntrusted(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID *ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus
) {
  PLOG(plog::info) << "LsaApCallPackageUntrusted";
  return 0;
}

extern "C" NTSTATUS NTAPI
LsaApCallPackagePassthrough(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID *ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus
) {
  PLOG(plog::info) << "LsaApCallPackagePassthrough";
  return 0;
}
