#ifndef LSA_AP_MAIN_H_
#define LSA_AP_MAIN_H_

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <Windows.h>
#include <Sspi.h>
#include <Ntsecapi.h>
#include <Ntsecpkg.h>

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
);

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
);

extern "C" VOID NTAPI
LsaApLogonTerminated(
    _In_
    PLUID LogonId
);

extern "C" NTSTATUS NTAPI
LsaApLogonUser(PLSA_CLIENT_REQUEST ClientRequest,
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
               PLSA_UNICODE_STRING *AuthenticatingAuthority);

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
);

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
);


extern "C" NTSTATUS NTAPI
LsaApCallPackageUntrusted(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID               ProtocolSubmitBuffer,
    PVOID               ClientBufferBase,
    ULONG               SubmitBufferLength,
    PVOID               *ProtocolReturnBuffer,
    PULONG              ReturnBufferLength,
    PNTSTATUS           ProtocolStatus
);

extern "C" NTSTATUS NTAPI
LsaApCallPackagePassthrough(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID *ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus
);

#endif /* LSA_AP_MAIN_H_ */
