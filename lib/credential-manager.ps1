# Credential Manager bridge for the ZCode keyring credential store.
#
# Reads one JSON request on stdin:
#   { "action": "read" | "write" | "delete",
#     "target": "<user>.<service>", "user": "<user>",
#     "blobB64": "<base64 UTF-16LE blob, write only>" }
#
# Writes exactly one JSON response on the last stdout line:
#   read   -> { ok: true, found: true|false, blobB64?: "..." }
#   write  -> { ok: true }
#   delete -> { ok: true, deleted: true|false }
#   error  -> { ok: false, error: { code, message } }

$ErrorActionPreference = 'Stop'

function Fail([string]$code, [string]$message) {
    @{ ok = $false; error = @{ code = $code; message = $message } } |
        ConvertTo-Json -Compress -Depth 5
    exit 0
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    Fail 'UNSUPPORTED_PLATFORM' 'Windows Credential Manager bridge requires Windows'
}

try {
    $reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), [System.Text.Encoding]::UTF8)
    $requestText = $reader.ReadToEnd()
} catch {
    Fail 'KEYRING_UNAVAILABLE' "failed to read request: $($_.Exception.Message)"
}
if ([string]::IsNullOrWhiteSpace($requestText)) {
    Fail 'KEYRING_UNAVAILABLE' 'empty request'
}

try {
    $request = $requestText | ConvertFrom-Json
} catch {
    Fail 'KEYRING_UNAVAILABLE' "invalid request JSON: $($_.Exception.Message)"
}

$action = "$($request.action)".ToLowerInvariant()
$target = "$($request.target)"
$user = "$($request.user)"
if (-not $target -or -not $user) {
    Fail 'KEYRING_UNAVAILABLE' 'request needs target and user'
}
if ($action -notin @('read', 'write', 'delete')) {
    Fail 'KEYRING_UNAVAILABLE' "unsupported action: $action"
}

if (-not ('ZCodeKeyring.NativeCredential' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ZCodeKeyring
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    public static class NativeCredential
    {
        public const uint GenericType = 1;
        public const uint LocalMachinePersist = 2;
        public const int NotFound = 1168;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredReadW(string target, uint type, int flags, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredWriteW(ref CREDENTIAL credential, int flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredDeleteW(string target, uint type, int flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern void CredFree(IntPtr buffer);

        public static Win32Exception LastError()
        {
            return new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
}

try {
    switch ($action) {
        'read' {
            $ptr = [IntPtr]::Zero
            $found = [ZCodeKeyring.NativeCredential]::CredReadW($target, [ZCodeKeyring.NativeCredential]::GenericType, 0, [ref]$ptr)
            if (-not $found) {
                $lastError = [ZCodeKeyring.NativeCredential]::LastError()
                if ($lastError.NativeErrorCode -eq [ZCodeKeyring.NativeCredential]::NotFound) {
                    @{ ok = $true; found = $false } | ConvertTo-Json -Compress
                    exit 0
                }
                Fail 'KEYRING_UNAVAILABLE' "CredRead failed: $($lastError.Message)"
            }
            try {
                $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][ZCodeKeyring.Credential])
            } catch {
                $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [ZCodeKeyring.Credential])
            }
            $size = [int]$credential.CredentialBlobSize
            $blob = New-Object byte[] $size
            if ($size -gt 0) {
                [System.Runtime.InteropServices.Marshal]::Copy($credential.CredentialBlob, $blob, 0, $size)
            }
            [ZCodeKeyring.NativeCredential]::CredFree($ptr)
            @{ ok = $true; found = $true; blobB64 = [Convert]::ToBase64String($blob) } |
                ConvertTo-Json -Compress -Depth 5
        }
        'write' {
            if (-not $request.blobB64) {
                Fail 'KEYRING_UNAVAILABLE' 'write request needs blobB64'
            }
            try {
                $blob = [Convert]::FromBase64String("$($request.blobB64)")
            } catch {
                Fail 'KEYRING_UNAVAILABLE' "invalid base64 blob: $($_.Exception.Message)"
            }
            $targetPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($target)
            $userPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($user)
            $blobPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([Math]::Max($blob.Length, 1))
            try {
                if ($blob.Length -gt 0) {
                    [System.Runtime.InteropServices.Marshal]::Copy($blob, 0, $blobPtr, $blob.Length)
                }
                $credential = New-Object ZCodeKeyring.Credential
                $credential.Flags = 0
                $credential.Type = [ZCodeKeyring.NativeCredential]::GenericType
                $credential.TargetName = $targetPtr
                $credential.Comment = [IntPtr]::Zero
                $credential.CredentialBlobSize = [uint32]$blob.Length
                $credential.CredentialBlob = $blobPtr
                $credential.Persist = [ZCodeKeyring.NativeCredential]::LocalMachinePersist
                $credential.AttributeCount = 0
                $credential.Attributes = [IntPtr]::Zero
                $credential.TargetAlias = [IntPtr]::Zero
                $credential.UserName = $userPtr
                if (-not [ZCodeKeyring.NativeCredential]::CredWriteW([ref]$credential, 0)) {
                    $lastError = [ZCodeKeyring.NativeCredential]::LastError()
                    Fail 'KEYRING_UNAVAILABLE' "CredWrite failed: $($lastError.Message)"
                }
                @{ ok = $true } | ConvertTo-Json -Compress
            } finally {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($blobPtr)
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($targetPtr)
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($userPtr)
            }
        }
        'delete' {
            $deleted = [ZCodeKeyring.NativeCredential]::CredDeleteW($target, [ZCodeKeyring.NativeCredential]::GenericType, 0)
            if (-not $deleted) {
                $lastError = [ZCodeKeyring.NativeCredential]::LastError()
                if ($lastError.NativeErrorCode -eq [ZCodeKeyring.NativeCredential]::NotFound) {
                    @{ ok = $true; deleted = $false } | ConvertTo-Json -Compress
                    exit 0
                }
                Fail 'KEYRING_UNAVAILABLE' "CredDelete failed: $($lastError.Message)"
            }
            @{ ok = $true; deleted = $true } | ConvertTo-Json -Compress
        }
    }
} catch {
    Fail 'KEYRING_UNAVAILABLE' "credential bridge failed: $($_.Exception.Message)"
}
