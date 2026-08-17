#Requires -Version 5.1
<#
.SYNOPSIS
    GPTNiX Watcher M3A provisioning bridge (Windows).

.DESCRIPTION
    Forwards the GPTNIX_WATCHER_M3A_PROVISION_V1 wire protocol (magic "GNX3",
    version 1, 8-byte header, 1..4096-byte TOKEN_FRAME payload, five message
    types) between the physical Watcher's console UART and the GPTNiX backend's
    M3A provisioning host runner, reached over a non-PTY SSH channel whose
    remote fd3 carries the binary protocol stream (fd1/fd2 stay ordinary log
    channels -- see the backend's own PROTOCOL_OUTPUT_FD contract).

    Operational sequence is intentionally: operator starts this bridge, opens
    the COM port, resets/power-cycles the Watcher when instructed, and ONLY
    once the device's own BRIDGE_READY frame is observed on the wire does this
    bridge start the backend SSH session -- never before.

    Uses only built-in .NET types (System.IO.Ports.SerialPort,
    System.Diagnostics.Process) and the Windows OpenSSH client already present
    on the runner/operator machine. No third-party PowerShell module, no
    package install.

    Secret hygiene: the Firebase device ID token is carried ONLY as byte[]
    values passed directly between the backend's binary fd3 stream and the
    device serial port -- it is never converted to a .NET string, never
    written to a temp file/clipboard/environment/shell variable/command-line
    argument, and never printed. Token-bearing byte[] buffers are cleared with
    [Array]::Clear() in a finally block immediately after their one use. As
    with the firmware/backend siblings of this protocol, this script does not
    claim to be able to zero every hidden runtime copy .NET/PowerShell's own
    marshaling may transiently create when a byte[] crosses a scriptblock or
    pipeline boundary -- only that this script's own long-lived references are
    minimized and its own owned buffers are cleared.

.PARAMETER SelfTest
    Runs the fully offline protocol/state-machine self-test: never opens a
    serial port, never starts SSH, never makes a network call, uses only
    synthetic in-memory fixtures. Exits 0 only on PASS.

.PARAMETER LiveAuthorized
    Required in addition to -ComPort/-SshTarget to run the live bridge. A
    separate, explicit flag is required for a real provisioning attempt.

.PARAMETER ComPort
    Windows COM port name (e.g. "COM5") the physical Watcher is attached to.

.PARAMETER SshTarget
    SSH destination (user@host) for the backend host. Non-secret, but its
    shape is validated before use; never embeds a credential.

.PARAMETER BaudRate
    Serial baud rate. Default 115200 (the pinned firmware console baud rate).

.PARAMETER DeviceReadyTimeoutSeconds
    Bounded wait for the device's own BRIDGE_READY frame before this bridge
    gives up and refuses to start the backend SSH session. Default 60.

.PARAMETER ProtocolTimeoutSeconds
    Bounded wait for each subsequent protocol exchange (TOKEN_STAGED,
    PROVISION_COMMIT/ABORT, the diagnostic device-READY observation window).
    Default 15.
#>
[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$LiveAuthorized,
    [string]$ComPort = '',
    [string]$SshTarget = '',
    [int]$BaudRate = 115200,
    [int]$DeviceReadyTimeoutSeconds = 60,
    [int]$ProtocolTimeoutSeconds = 15
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# GPTNIX_WATCHER_M3A_PROVISION_V1 protocol constants -- must match the backend
# and firmware exactly. Do not introduce a different protocol version.
# -----------------------------------------------------------------------------
$Script:GwMagic            = [byte[]](0x47, 0x4E, 0x58, 0x33) # "GNX3"
$Script:GwVersion           = [byte]0x01
$Script:GwHeaderBytes       = 8
$Script:GwMaxPayloadBytes   = 4096

$Script:GwMsgBridgeReady     = [byte]0x01
$Script:GwMsgTokenFrame      = [byte]0x02
$Script:GwMsgTokenStaged     = [byte]0x03
$Script:GwMsgProvisionCommit = [byte]0x04
$Script:GwMsgProvisionAbort  = [byte]0x05

# Cleanup grace AFTER a protocol deadline has already expired -- not additional protocol time. No protocol
# byte may be accepted and no serial write may occur during this window; it exists solely to give a cancelled
# read worker a bounded chance to actually quiesce before this process either continues or fail-closed exits.
$Script:GwReadCancelGraceMs = 2000

# -----------------------------------------------------------------------------
# GptnixWatcherBoundedProcessRead -- hard-bounded synchronous Process-stdout read.
#
# WHY THIS EXISTS (primary-source justification, not blog/StackOverflow-derived):
#   - .NET's Process class redirects StandardOutput using the Win32 CreatePipe() anonymous-pipe API (see
#     dotnet/runtime Process.Windows.cs). CreatePipe()'s signature has no FILE_FLAG_OVERLAPPED-equivalent
#     parameter at all -- unlike CreateNamedPipe() -- so a pipe handle it returns can never be opened for
#     overlapped/asynchronous I/O.
#   - dotnet/runtime's Process stream-construction helper builds the FileStream as
#     `new FileStream(handle, access, StreamBufferSize, handle.IsAsync)` -- i.e. isAsync tracks the handle's
#     own capability, which for a CreatePipe() handle is always false.
#   - Per Microsoft's own Stream.BeginRead documentation (learn.microsoft.com/en-us/dotnet/api/
#     system.io.stream.beginread, Remarks): "The default implementation of BeginRead on a stream calls the
#     Read method synchronously, which means that Read might block on some streams. However, instances of
#     classes such as FileStream ... fully support asynchronous operations IF THE INSTANCES HAVE BEEN OPENED
#     ASYNCHRONOUSLY. ... EndRead must be called once for every call to BeginRead."
#   A Process-redirected StandardOutput FileStream is therefore NOT guaranteed to have been opened
#   asynchronously, so Stream.BeginRead() on it can silently fall back to a call that itself blocks
#   synchronously -- meaning `AsyncWaitHandle.WaitOne(remainingMs)` can never even be reached in time. This
#   bridge must not depend on that assumption for a security-relevant deadline.
#
# The fix: isolate the actual (possibly blocking) Stream.Read() call onto one dedicated worker thread per
# read attempt; the calling thread only ever waits, bounded, for that worker to signal completion. On
# timeout, the worker's pending synchronous I/O is cancelled via the real Win32 CancelSynchronousIo() API
# (learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio: "marks pending
# synchronous I/O operations that are issued by the specified thread as canceled" -- takes a THREAD handle
# with THREAD_TERMINATE access, does not itself wait for completion), the backend process/stream are torn
# down as a second cancellation vector, and this method does not return -- and therefore this bridge never
# clears/reuses the owned buffer or continues to serial/REPL -- until the worker is PROVEN to have quiesced.
# If quiescence cannot be proven within a small bounded grace period, the entire bridge process is terminated
# fail-closed via a single Environment.FailFast() call site rather than ever risking a live worker thread
# that could still mutate a cleared/reused buffer or be mistaken for a clean state.
#
# This type knows nothing about the GNX3 protocol, TOKEN_FRAME/TOKEN_STAGED/COMMIT/ABORT, Firebase, Gemini,
# or serial -- its only responsibility is a hard-bounded read from an arbitrary Process-backed Stream.
# -----------------------------------------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'GptnixWatcherBoundedProcessRead').Type) {
    $Script:GwBoundedProcessReadSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

public class GptnixWatcherBoundedReadResult
{
    public string Status;
    public int BytesRead;
}

public static class GptnixWatcherBoundedProcessRead
{
    private const uint THREAD_TERMINATE = 0x0001;

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelSynchronousIo(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // Reads at most `count` bytes once, hard-bounded by timeoutMs. Never returns while the dedicated read
    // worker could still be mutating `buffer` -- either the worker is proven quiesced first, or this process
    // is terminated via FailFast and never returns at all.
    public static GptnixWatcherBoundedReadResult ReadOnceBounded(Stream stream, Process process, byte[] buffer, int offset, int count, int timeoutMs, int cancelGraceMs)
    {
        object gate = new object();
        bool threadIdReady = false;
        uint workerThreadId = 0;
        bool completed = false;
        int bytesRead = 0;
        bool ioError = false;

        Thread worker = new Thread(delegate()
        {
            lock (gate)
            {
                workerThreadId = GetCurrentThreadId();
                threadIdReady = true;
                Monitor.PulseAll(gate);
            }
            int n = 0;
            bool failed = false;
            try
            {
                n = stream.Read(buffer, offset, count);
            }
            catch
            {
                failed = true;
            }
            lock (gate)
            {
                bytesRead = n;
                ioError = failed;
                completed = true;
                Monitor.PulseAll(gate);
            }
        });
        worker.IsBackground = true;
        worker.Start();

        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        lock (gate)
        {
            while (!completed)
            {
                double remaining = (deadline - DateTime.UtcNow).TotalMilliseconds;
                if (remaining <= 0) break;
                Monitor.Wait(gate, (int)remaining);
            }
            if (completed)
            {
                if (ioError)
                {
                    GptnixWatcherBoundedReadResult failResult = new GptnixWatcherBoundedReadResult();
                    failResult.Status = "io_failure";
                    failResult.BytesRead = 0;
                    return failResult;
                }
                GptnixWatcherBoundedReadResult okResult = new GptnixWatcherBoundedReadResult();
                if (bytesRead <= 0)
                {
                    okResult.Status = "eof";
                    okResult.BytesRead = 0;
                }
                else
                {
                    okResult.Status = "success";
                    okResult.BytesRead = bytesRead;
                }
                return okResult;
            }
        }

        // Timed out with the worker still (as far as we know) running: cancel its pending synchronous I/O,
        // terminate the backend process, close the stream, then wait bounded for it to actually quiesce.
        bool haveThreadId;
        uint capturedThreadId;
        lock (gate)
        {
            haveThreadId = threadIdReady;
            capturedThreadId = workerThreadId;
        }
        IntPtr threadHandle = IntPtr.Zero;
        if (haveThreadId)
        {
            threadHandle = OpenThread(THREAD_TERMINATE, false, capturedThreadId);
        }
        try
        {
            if (threadHandle != IntPtr.Zero)
            {
                // Best-effort: a false/ERROR_NOT_FOUND result here (documented by Microsoft as a normal
                // outcome when no matching pending request is found, e.g. a benign completion race) is not
                // itself fatal -- quiescence is proven below by actually waiting for the worker, not by this
                // return value.
                CancelSynchronousIo(threadHandle);
            }
        }
        finally
        {
            if (threadHandle != IntPtr.Zero)
            {
                CloseHandle(threadHandle);
            }
        }

        try
        {
            if (process != null && !process.HasExited)
            {
                process.Kill();
            }
        }
        catch { }

        try
        {
            stream.Close();
        }
        catch { }

        DateTime graceDeadline = DateTime.UtcNow.AddMilliseconds(cancelGraceMs);
        bool quiesced;
        lock (gate)
        {
            while (!completed)
            {
                double remaining = (graceDeadline - DateTime.UtcNow).TotalMilliseconds;
                if (remaining <= 0) break;
                Monitor.Wait(gate, (int)remaining);
            }
            quiesced = completed;
        }

        if (!quiesced)
        {
            // Security kill-switch, exactly one call site: an I/O state we cannot prove clean must never be
            // allowed to continue toward a buffer clear, a serial write, or REPL orchestration. Fixed,
            // non-secret message -- no exception object, no interpolation, no buffer content.
            Environment.FailFast("gptnix_bounded_read_worker_not_quiesced");
        }

        GptnixWatcherBoundedReadResult timeoutResult = new GptnixWatcherBoundedReadResult();
        timeoutResult.Status = "timeout";
        timeoutResult.BytesRead = 0;
        return timeoutResult;
    }
}
'@
    Add-Type -TypeDefinition $Script:GwBoundedProcessReadSource -Language CSharp
}

function New-GwFrame {
    <# Builds one protocol frame as a byte[]. Payload is always byte[] --
       never a .NET string -- so a caller can never accidentally re-encode a
       token through a text code path. #>
    param(
        [Parameter(Mandatory = $true)][byte]$Type,
        [byte[]]$Payload = @()
    )
    if ($Payload.Length -gt $Script:GwMaxPayloadBytes) {
        throw 'gw_payload_too_large'
    }
    $len = $Payload.Length
    $frame = New-Object byte[] ($Script:GwHeaderBytes + $len)
    [Array]::Copy($Script:GwMagic, 0, $frame, 0, 4)
    $frame[4] = $Script:GwVersion
    $frame[5] = $Type
    $frame[6] = [byte](($len -shr 8) -band 0xFF)
    $frame[7] = [byte]($len -band 0xFF)
    if ($len -gt 0) {
        [Array]::Copy($Payload, 0, $frame, $Script:GwHeaderBytes, $len)
    }
    return $frame
}

function Test-GwFrameHeader {
    <# Validates an exact 8-byte header array. Returns @{Ok;Type;Length} on
       success or @{Ok=$false;Reason=<classified string>} on failure -- never
       includes the raw header bytes in the returned reason. #>
    param([byte[]]$Header)
    if ($null -eq $Header -or $Header.Length -ne $Script:GwHeaderBytes) {
        return @{ Ok = $false; Reason = 'header_length' }
    }
    for ($i = 0; $i -lt 4; $i++) {
        if ($Header[$i] -ne $Script:GwMagic[$i]) {
            return @{ Ok = $false; Reason = 'magic' }
        }
    }
    if ($Header[4] -ne $Script:GwVersion) {
        return @{ Ok = $false; Reason = 'version' }
    }
    $type = $Header[5]
    $len = ([int]$Header[6] -shl 8) -bor [int]$Header[7]
    if ($len -gt $Script:GwMaxPayloadBytes) {
        return @{ Ok = $false; Reason = 'length' }
    }
    return @{ Ok = $true; Type = $type; Length = $len }
}

function Test-GwProtocolTimeoutSecondsValid {
    <# Pure, directly testable: -ProtocolTimeoutSeconds must stay well below the firmware's own
       GW_TOKEN_FRAME_WAIT_MS=60000 window. Used by both the script entry point and the self-test. #>
    param([int]$Seconds)
    return ($Seconds -ge 1 -and $Seconds -le 15)
}

function Test-GwByteArrayEqual {
    param([byte[]]$A, [byte[]]$B)
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) {
        if ($A[$i] -ne $B[$i]) { return $false }
    }
    return $true
}

function Wait-GwBridgeReady {
    <# Scans a byte source for a valid zero-payload BRIDGE_READY frame,
       ignoring arbitrary non-protocol noise bytes -- never prints ignored
       bytes. $ReadByte is a scriptblock returning one byte (0-255) or $null
       on a bounded per-call timeout/no-data. Returns $true if BRIDGE_READY
       was found within $TimeoutSeconds of wall-clock time, else $false. #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ReadByte,
        [int]$TimeoutSeconds = 60
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $window = New-Object System.Collections.Generic.Queue[byte]
    while ((Get-Date) -lt $deadline) {
        $b = & $ReadByte
        if ($null -eq $b) { continue }
        $window.Enqueue([byte]$b)
        while ($window.Count -gt $Script:GwHeaderBytes) { [void]$window.Dequeue() }
        if ($window.Count -eq $Script:GwHeaderBytes) {
            $parsed = Test-GwFrameHeader -Header $window.ToArray()
            if ($parsed.Ok -and $parsed.Type -eq $Script:GwMsgBridgeReady -and $parsed.Length -eq 0) {
                return $true
            }
        }
    }
    return $false
}

function Receive-GwTokenFrameAndForward {
    <# Reads exactly one TOKEN_FRAME via $ReadBytesExact (backend fd3 stream),
       forwards the exact raw frame bytes to $WriteBytes (serial) unmodified,
       and clears the local byte[] copy in a finally block immediately after
       the write. Never converts the payload to a String, never prints it. #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ReadBytesExact, # (count) -> byte[] or $null
        [Parameter(Mandatory = $true)][scriptblock]$WriteBytes      # (byte[]) -> void
    )
    $header = & $ReadBytesExact $Script:GwHeaderBytes
    $parsed = Test-GwFrameHeader -Header $header
    if (-not $parsed.Ok -or $parsed.Type -ne $Script:GwMsgTokenFrame -or $parsed.Length -lt 1) {
        throw "gw_token_frame_invalid: $($parsed.Reason)"
    }
    $payload = & $ReadBytesExact $parsed.Length
    if ($null -eq $payload) {
        throw 'gw_token_frame_payload_read_failed'
    }
    $frame = New-Object byte[] ($Script:GwHeaderBytes + $parsed.Length)
    [Array]::Copy($header, 0, $frame, 0, $Script:GwHeaderBytes)
    [Array]::Copy($payload, 0, $frame, $Script:GwHeaderBytes, $parsed.Length)
    try {
        & $WriteBytes $frame
    } finally {
        [Array]::Clear($frame, 0, $frame.Length)
        [Array]::Clear($payload, 0, $payload.Length)
    }
}

function Confirm-GwDeviceTokenStaged {
    <# Reads exactly one control frame from the DEVICE and requires it to be a
       valid zero-payload TOKEN_STAGED. The bridge never fabricates this frame
       itself -- it only ever forwards one actually received from the device
       (see F5/F6). Throws on anything else -- never returns a fabricated
       success. #>
    param([Parameter(Mandatory = $true)][scriptblock]$ReadBytesExact)
    $header = & $ReadBytesExact $Script:GwHeaderBytes
    $parsed = Test-GwFrameHeader -Header $header
    if (-not $parsed.Ok -or $parsed.Type -ne $Script:GwMsgTokenStaged -or $parsed.Length -ne 0) {
        throw "gw_token_staged_not_confirmed: $($parsed.Reason)"
    }
    return $true
}

function Read-GwStreamExactBounded {
    <# The ONE canonical bounded backend-stream read primitive. Reads exactly $Count bytes from $Stream,
       governed by a single deadline ($Stopwatch elapsed vs $BudgetMs) that the CALLER owns and may share
       across multiple invocations (e.g. one TOKEN_FRAME header read followed by one payload read sharing the
       SAME deadline -- see Phase F). Each chunk is read via
       GptnixWatcherBoundedProcessRead.ReadOnceBounded(), which performs the potentially-blocking
       Stream.Read() call on a dedicated worker thread and hard-cancels it with the real Win32
       CancelSynchronousIo() API if the deadline expires -- this never depends on Stream.BeginRead()/
       EndRead()/ReadAsync() being genuinely non-blocking, which primary Microsoft documentation does NOT
       guarantee for a Process-redirected stdout pipe stream (see the C# source comment above for the exact
       citations). ReadOnceBounded() never returns until the read worker is PROVEN quiesced -- or the whole
       bridge process is terminated fail-closed if it cannot be -- so by the time this function scrubs its
       owned buffer and returns, no other thread can still be mutating it. #>
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$Count,
        [Parameter(Mandatory = $true)][System.Diagnostics.Stopwatch]$Stopwatch,
        [Parameter(Mandatory = $true)][int]$BudgetMs
    )
    $buf = New-Object byte[] $Count
    $got = 0
    while ($got -lt $Count) {
        $remainingMs = $BudgetMs - [int]$Stopwatch.ElapsedMilliseconds
        if ($remainingMs -le 0) {
            [Array]::Clear($buf, 0, $buf.Length)
            return @{ Ok = $false; Reason = 'timeout' }
        }
        $result = [GptnixWatcherBoundedProcessRead]::ReadOnceBounded($Stream, $Process, $buf, $got, $Count - $got, $remainingMs, $Script:GwReadCancelGraceMs)
        if ($result.Status -eq 'timeout') {
            [Array]::Clear($buf, 0, $buf.Length)
            return @{ Ok = $false; Reason = 'timeout' }
        }
        if ($result.Status -eq 'eof') {
            [Array]::Clear($buf, 0, $buf.Length)
            return @{ Ok = $false; Reason = 'eof' }
        }
        if ($result.Status -eq 'io_failure') {
            [Array]::Clear($buf, 0, $buf.Length)
            return @{ Ok = $false; Reason = 'io' }
        }
        $got += $result.BytesRead
    }
    return @{ Ok = $true; Bytes = $buf }
}

function Start-GwBackendProcess {
    <# Starts the canonical backend M3A provisioning launcher over a non-PTY
       SSH session. StandardOutput.BaseStream is the clean binary fd3 protocol
       stream; StandardInput.BaseStream is the upstream write channel. No
       secret in SSH args -- the remote gates/UIDs are container
       configuration, never passed on this command line. #>
    param([Parameter(Mandatory = $true)][string]$SshTarget)

    $remoteCommand = "docker exec -i gptnix-backend sh -c 'exec env V2_WATCHER_M3A_PROVISION=1 V2_WATCHER_M3A_LIVE_AUTHORIZED=1 node src/v2/canary/watcherM3AProvisionRunner.js 3>&1 1>&2'"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'ssh.exe'
    # -T explicitly disables PTY allocation -- required so StandardOutput.BaseStream stays clean binary, never
    # terminal-mangled.
    $psi.Arguments = "-T $SshTarget `"$remoteCommand`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true

    return [System.Diagnostics.Process]::Start($psi)
}

function New-GwSelfTestChildProcess {
    <# SelfTest-only fixture starter: a LOCAL powershell.exe child (never the SSH client, never a network endpoint)
       with redirected binary stdout, used ONLY to prove Read-GwStreamExactBounded against the ACTUAL
       System.Diagnostics.Process.StandardOutput.BaseStream transport primitive -- not merely a synthetic
       AnonymousPipeClientStream. The child writes only fixed, non-secret synthetic bytes supplied by
       $ChildCommand; this helper itself never touches network/serial. #>
    param([Parameter(Mandatory = $true)][string]$ChildCommand)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -NonInteractive -Command `"$ChildCommand`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true
    return [System.Diagnostics.Process]::Start($psi)
}

function Invoke-GwLiveBridge {
    <# F2-F7: the full live device<->backend bridging sequence. Never executed
       by CI or -SelfTest -- this task authorizes code only, no live run. #>
    param(
        [Parameter(Mandatory = $true)][string]$ComPort,
        [Parameter(Mandatory = $true)][string]$SshTarget,
        [int]$BaudRate,
        [int]$DeviceReadyTimeoutSeconds,
        [int]$ProtocolTimeoutSeconds
    )

    $port = New-Object -TypeName 'System.IO.Ports.SerialPort' -ArgumentList $ComPort, $BaudRate, ([System.IO.Ports.Parity]::None), 8, ([System.IO.Ports.StopBits]::One)
    $port.Handshake = [System.IO.Ports.Handshake]::None
    $port.DtrEnable = $false
    $port.RtsEnable = $false
    $port.ReadTimeout = 1000
    $port.Open()

    $proc = $null
    try {
        $readDeviceByte = {
            try { return [byte]$port.ReadByte() } catch [System.TimeoutException] { return $null }
        }.GetNewClosure()

        Write-Output '[M3A_BRIDGE] waiting for device BRIDGE_READY before starting backend session'
        $found = Wait-GwBridgeReady -ReadByte $readDeviceByte -TimeoutSeconds $DeviceReadyTimeoutSeconds
        if (-not $found) {
            Write-Error '[M3A_BRIDGE] device_ready: timeout -- refusing to start backend session'
            return 2
        }
        Write-Output '[M3A_BRIDGE] device_ready: true'

        $proc = Start-GwBackendProcess -SshTarget $SshTarget
        $inStream = $proc.StandardInput.BaseStream
        $outStream = $proc.StandardOutput.BaseStream

        $readyFrame = New-GwFrame -Type $Script:GwMsgBridgeReady -Payload @()
        $inStream.Write($readyFrame, 0, $readyFrame.Length)
        $inStream.Flush()

        # D3: the TOKEN_FRAME header and its payload share ONE deadline -- this Stopwatch is created once,
        # before the header read, and both the header-read and payload-read invocations of $readBackendExact
        # (inside Receive-GwTokenFrameAndForward) consume the SAME remaining budget. A late backend byte that
        # arrives after this budget expires can never be handed to the serial-write callback:
        # Receive-GwTokenFrameAndForward already throws before calling $WriteBytes on any $null read (see its
        # own header_length/payload_read_failed checks), and Read-GwStreamExactBounded never exposes a timed-
        # out read's buffer to this closure in the first place.
        $tokenFrameStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $tokenFrameBudgetMs = $ProtocolTimeoutSeconds * 1000
        $readBackendExact = {
            param($count)
            $result = Read-GwStreamExactBounded -Stream $outStream -Process $proc -Count $count -Stopwatch $tokenFrameStopwatch -BudgetMs $tokenFrameBudgetMs
            if (-not $result.Ok) { return $null }
            return $result.Bytes
        }.GetNewClosure()

        $writeSerialBytes = {
            param($bytes) $port.Write($bytes, 0, $bytes.Length)
        }.GetNewClosure()

        try {
            Receive-GwTokenFrameAndForward -ReadBytesExact $readBackendExact -WriteBytes $writeSerialBytes
        } catch {
            # Bounded backend read failed (timeout/EOF) or the frame was malformed -- no serial write occurred
            # (see the comment above). Terminate the backend transport now so no abandoned async read can ever
            # later deliver a late TOKEN_FRAME while the device may already have left its raw provisioning
            # window; the outer finally also tears this down defensively.
            Write-Error '[M3A_BRIDGE] backend_token_frame: bounded read failed or frame invalid'
            return 2
        }

        $readSerialExact = {
            param($count)
            $buf = New-Object byte[] $count
            $got = 0
            $deadline = (Get-Date).AddSeconds($ProtocolTimeoutSeconds)
            while ($got -lt $count) {
                if ((Get-Date) -ge $deadline) { return $null }
                try {
                    $n = $port.Read($buf, $got, $count - $got)
                } catch [System.TimeoutException] {
                    $n = 0
                }
                $got += $n
            }
            return $buf
        }.GetNewClosure()

        Confirm-GwDeviceTokenStaged -ReadBytesExact $readSerialExact | Out-Null

        $stagedFrame = New-GwFrame -Type $Script:GwMsgTokenStaged -Payload @()
        $inStream.Write($stagedFrame, 0, $stagedFrame.Length)
        $inStream.Flush()
        # ---- Past this point the bridge MUST NOT originate its own PROVISION_ABORT. It may only forward
        # whatever decision frame it actually receives from the backend, byte-for-byte, never reconstructed. ----

        # D6: a FRESH bounded deadline for the post-staged backend decision (COMMIT/ABORT), separate from the
        # TOKEN_FRAME deadline above. On timeout/EOF here the classification below already falls through to
        # "malformed" (Test-GwFrameHeader on a $null header) -- no control frame is ever sent to the device on
        # that path, and the bridge still never fabricates/originates its own ABORT. The device's own COMMIT
        # timeout remains the canonical cleanup mechanism for this case.
        $decisionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $decisionBudgetMs = $ProtocolTimeoutSeconds * 1000
        $readBackendDecisionExact = {
            param($count)
            $result = Read-GwStreamExactBounded -Stream $outStream -Process $proc -Count $count -Stopwatch $decisionStopwatch -BudgetMs $decisionBudgetMs
            if (-not $result.Ok) { return $null }
            return $result.Bytes
        }.GetNewClosure()

        $decisionHeader = & $readBackendDecisionExact $Script:GwHeaderBytes
        $decisionParsed = Test-GwFrameHeader -Header $decisionHeader
        $isCommit = $decisionParsed.Ok -and $decisionParsed.Length -eq 0 -and $decisionParsed.Type -eq $Script:GwMsgProvisionCommit
        $isAbort = $decisionParsed.Ok -and $decisionParsed.Length -eq 0 -and $decisionParsed.Type -eq $Script:GwMsgProvisionAbort
        if (-not ($isCommit -or $isAbort)) {
            Write-Error '[M3A_BRIDGE] backend_decision: malformed'
            return 2
        }
        $port.Write($decisionHeader, 0, $decisionHeader.Length)

        if ($isAbort) {
            Write-Output '[M3A_BRIDGE] decision: abort'
            return 0
        }
        Write-Output '[M3A_BRIDGE] decision: commit'

        # F7 -- bounded, diagnostics-only observation window for the device READY marker. Never part of
        # security/commit semantics; never echoes arbitrary device log bytes.
        $marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')
        $deadline = (Get-Date).AddSeconds($ProtocolTimeoutSeconds)
        $window = New-Object System.Collections.Generic.Queue[byte]
        $deviceReady = $false
        while ((Get-Date) -lt $deadline) {
            try {
                $b = $port.ReadByte()
            } catch [System.TimeoutException] {
                continue
            }
            if ($b -lt 0) { continue }
            $window.Enqueue([byte]$b)
            while ($window.Count -gt $marker.Length) { [void]$window.Dequeue() }
            if ($window.Count -eq $marker.Length -and (Test-GwByteArrayEqual -A $window.ToArray() -B $marker)) {
                $deviceReady = $true
                break
            }
        }
        if ($deviceReady) {
            Write-Output '[M3A_BRIDGE] device_ready: true'
        } else {
            Write-Output '[M3A_BRIDGE] device_ready: timeout'
        }
        return 0
    } finally {
        # D7: single teardown path -- process (and its redirected streams), then serial. Every step is
        # individually best-effort/swallowed so one failure never blocks the next, and no exception here ever
        # carries secret material (none of these calls touch token/frame content).
        if ($null -ne $proc) {
            try {
                if (-not $proc.HasExited) { $proc.Kill() }
            } catch { }
            try { $proc.StandardInput.Close() } catch { }
            try { $proc.StandardOutput.Close() } catch { }
            try { $proc.Dispose() } catch { }
        }
        if ($null -ne $port -and $port.IsOpen) {
            try { $port.Close() } catch { }
        }
    }
}

function Invoke-GwSelfTest {
    <# F9: fully offline. Never opens serial, never starts SSH, never makes a
       network call -- exercises the SAME functions the live bridge uses,
       against synthetic in-memory fixtures only. Returns a string[] of
       failure names (empty array = PASS). #>
    $failures = New-Object System.Collections.Generic.List[string]

    # 1. protocol constants
    if (-not (Test-GwByteArrayEqual -A $Script:GwMagic -B ([byte[]](0x47, 0x4E, 0x58, 0x33)))) { $failures.Add('magic_constant') }
    if ($Script:GwVersion -ne 0x01) { $failures.Add('version_constant') }
    if ($Script:GwHeaderBytes -ne 8) { $failures.Add('header_bytes_constant') }
    if ($Script:GwMaxPayloadBytes -ne 4096) { $failures.Add('max_payload_constant') }

    # 2. frame build/parse round-trip (1-byte TOKEN_FRAME)
    $frame = New-GwFrame -Type $Script:GwMsgTokenFrame -Payload ([byte[]](0x41))
    if ($frame.Length -ne ($Script:GwHeaderBytes + 1)) { $failures.Add('roundtrip_length') }
    $parsedHeader = Test-GwFrameHeader -Header $frame[0..($Script:GwHeaderBytes - 1)]
    if (-not $parsedHeader.Ok -or $parsedHeader.Type -ne $Script:GwMsgTokenFrame -or $parsedHeader.Length -ne 1) { $failures.Add('roundtrip_parse') }

    # 3. malformed magic rejected
    $badMagic = Test-GwFrameHeader -Header ([byte[]](0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00))
    if ($badMagic.Ok -or $badMagic.Reason -ne 'magic') { $failures.Add('bad_magic_not_rejected') }

    # 4. malformed version rejected
    $badVersionHeader = $frame[0..($Script:GwHeaderBytes - 1)].Clone()
    $badVersionHeader[4] = 0x02
    $badVersion = Test-GwFrameHeader -Header $badVersionHeader
    if ($badVersion.Ok -or $badVersion.Reason -ne 'version') { $failures.Add('bad_version_not_rejected') }

    # 5. malformed (oversized) length rejected
    $badLength = Test-GwFrameHeader -Header ([byte[]](0x47, 0x4E, 0x58, 0x33, 0x01, 0x02, 0xFF, 0xFF))
    if ($badLength.Ok -or $badLength.Reason -ne 'length') { $failures.Add('bad_length_not_rejected') }

    # 6. noise-scan -> BRIDGE_READY extraction, via a synthetic byte-source fixture
    $bridgeReadyFrame = New-GwFrame -Type $Script:GwMsgBridgeReady -Payload @()
    $noiseFixture = New-Object System.Collections.Generic.List[byte]
    $noiseFixture.AddRange([byte[]](0x0D, 0x0A, 0x41, 0x42, 0x43)) # arbitrary non-protocol log noise
    $noiseFixture.AddRange([byte[]]$bridgeReadyFrame)
    $fixtureArray = $noiseFixture.ToArray()
    # Deterministic mutable state owner: a captured scalar ($x = 0; $x++ inside a GetNewClosure() callback)
    # is not a reliable way to persist mutation across repeated invocations of the SAME closure instance on
    # Windows PowerShell -- mutating a PROPERTY on a captured reference-type object is unambiguous instead.
    $fixtureState = [pscustomobject]@{ Index = 0 }
    $fixtureReadByte = {
        if ($fixtureState.Index -ge $fixtureArray.Length) { return $null }
        $b = $fixtureArray[$fixtureState.Index]
        $fixtureState.Index++
        return $b
    }.GetNewClosure()
    if (-not (Wait-GwBridgeReady -ReadByte $fixtureReadByte -TimeoutSeconds 5)) { $failures.Add('noise_scan_bridge_ready_not_found') }

    # 6b. deterministic closure-state advancement: the fixture's shared state object must have consumed
    # every byte the moment the real BRIDGE_READY frame was matched (proves the mutation is visible across
    # every invocation of the SAME closure instance, not just some of them).
    if ($fixtureState.Index -ne $fixtureArray.Length) { $failures.Add('fixture_state_did_not_advance_deterministically') }

    # 7. TOKEN_FRAME forwarding buffer cleanup, via a synthetic fixture -- proves the byte[] the write
    # delegate saw is zeroized after the call, not merely that the source claims it (same object reference).
    $tokenPayload = [System.Text.Encoding]::ASCII.GetBytes('sentinel-selftest-token-fixture')
    $tokenFrame = New-GwFrame -Type $Script:GwMsgTokenFrame -Payload $tokenPayload
    $rxState = [pscustomobject]@{ Index = 0 }
    $readTokenExact = {
        param($count)
        if ($rxState.Index + $count -gt $tokenFrame.Length) { return $null }
        $slice = $tokenFrame[$rxState.Index..($rxState.Index + $count - 1)]
        $rxState.Index += $count
        return $slice
    }.GetNewClosure()
    $script:GwSelfTestCapturedFrame = $null
    $captureWrite = { param($bytes) $script:GwSelfTestCapturedFrame = $bytes }
    Receive-GwTokenFrameAndForward -ReadBytesExact $readTokenExact -WriteBytes $captureWrite
    if ($null -eq $script:GwSelfTestCapturedFrame) {
        $failures.Add('token_forward_not_captured')
    } elseif (($script:GwSelfTestCapturedFrame | Where-Object { $_ -ne 0 }).Count -ne 0) {
        $failures.Add('token_forward_not_cleared')
    }

    # 8. state guard: TOKEN_STAGED cannot be confirmed from anything other than a real device TOKEN_STAGED
    # fixture -- the bridge never fabricates it.
    $wrongFrame = New-GwFrame -Type $Script:GwMsgProvisionAbort -Payload @()
    $wrongState = [pscustomobject]@{ Index = 0 }
    $readWrong = {
        param($count)
        if ($wrongState.Index + $count -gt $wrongFrame.Length) { return $null }
        $slice = $wrongFrame[$wrongState.Index..($wrongState.Index + $count - 1)]
        $wrongState.Index += $count
        return $slice
    }.GetNewClosure()
    $rejectedWrong = $false
    try {
        Confirm-GwDeviceTokenStaged -ReadBytesExact $readWrong | Out-Null
    } catch {
        $rejectedWrong = $true
    }
    if (-not $rejectedWrong) { $failures.Add('token_staged_guard_accepted_wrong_frame') }

    $realStagedFrame = New-GwFrame -Type $Script:GwMsgTokenStaged -Payload @()
    $realState = [pscustomobject]@{ Index = 0 }
    $readReal = {
        param($count)
        if ($realState.Index + $count -gt $realStagedFrame.Length) { return $null }
        $slice = $realStagedFrame[$realState.Index..($realState.Index + $count - 1)]
        $realState.Index += $count
        return $slice
    }.GetNewClosure()
    $acceptedReal = $false
    try {
        $acceptedReal = Confirm-GwDeviceTokenStaged -ReadBytesExact $readReal
    } catch {
        $acceptedReal = $false
    }
    if (-not $acceptedReal) { $failures.Add('token_staged_guard_rejected_real_frame') }

    # The former "9"/"10" AnonymousPipeClientStream timeout/partial fixtures are retired: they called
    # Read-GwStreamExactBounded with an explicit null in place of a real backend Process, but that parameter is
    # a mandatory, non-null part of the canonical cancellation contract (it must be a real backend Process so a
    # timeout can CancelSynchronousIo/Kill/close it) -- so that call shape is not legitimate and Windows
    # PowerShell correctly rejects it at the parameter binder before this function body ever runs. The strictly
    # stronger J2/J3 fixtures below supersede this coverage against a REAL
    # System.Diagnostics.Process.StandardOutput.BaseStream (exact same timeout/partial-read behavior, but
    # through the actual live transport primitive instead of an AnonymousPipeClientStream stand-in).

    # J1-J6: the authoritative Windows fixtures -- a REAL local System.Diagnostics.Process with
    # RedirectStandardOutput=true, never merely an AnonymousPipeClientStream. The child is always
    # powershell.exe (never the SSH client), writes only fixed synthetic non-secret bytes, and this SelfTest never
    # opens a COM port, starts SSH, or makes a network call anywhere in this section.

    # J1. actual stream type proof -- diagnostic only, never dumps stream data.
    $childJ1 = New-GwSelfTestChildProcess -ChildCommand 'Start-Sleep -Milliseconds 50'
    try {
        $streamTypeName = $childJ1.StandardOutput.BaseStream.GetType().FullName
        if ([string]::IsNullOrEmpty($streamTypeName)) { $failures.Add('process_stdout_stream_type_unavailable') }
    } finally {
        try { if (-not $childJ1.HasExited) { $childJ1.Kill() } } catch { }
        $childJ1.WaitForExit(2000) | Out-Null
        $childJ1.Dispose()
    }

    # J2. hard timeout fixture: child writes zero bytes and sleeps well beyond the protocol budget.
    $childJ2 = New-GwSelfTestChildProcess -ChildCommand 'Start-Sleep -Milliseconds 3000'
    try {
        $swJ2 = [System.Diagnostics.Stopwatch]::StartNew()
        $resultJ2 = Read-GwStreamExactBounded -Stream $childJ2.StandardOutput.BaseStream -Process $childJ2 -Count $Script:GwHeaderBytes -Stopwatch $swJ2 -BudgetMs 300
        if ($resultJ2.Ok) {
            $failures.Add('process_stdout_timeout_not_classified')
        } elseif ($resultJ2.Reason -ne 'timeout') {
            $failures.Add('process_stdout_timeout_wrong_reason')
        }
        if ($swJ2.ElapsedMilliseconds -ge 2000) { $failures.Add('process_stdout_timeout_exceeded_conservative_ceiling') }
        $childJ2.WaitForExit(2000) | Out-Null
        if (-not $childJ2.HasExited) { $failures.Add('process_stdout_timeout_child_not_terminated') }
    } finally {
        try { if (-not $childJ2.HasExited) { $childJ2.Kill() } } catch { }
        $childJ2.Dispose()
    }

    # J3. partial process-stdout fixture: child writes 4 synthetic bytes then sleeps beyond budget; 8 bytes
    # requested. Must fail closed, never invoke the serial-write callback, and terminate the child.
    $childJ3 = New-GwSelfTestChildProcess -ChildCommand '$s = [Console]::OpenStandardOutput(); $b = [byte[]](0x47,0x4E,0x58,0x33); $s.Write($b, 0, $b.Length); $s.Flush(); Start-Sleep -Milliseconds 3000'
    try {
        $swJ3 = [System.Diagnostics.Stopwatch]::StartNew()
        $budgetJ3 = 300
        $readJ3Exact = {
            param($count)
            $r = Read-GwStreamExactBounded -Stream $childJ3.StandardOutput.BaseStream -Process $childJ3 -Count $count -Stopwatch $swJ3 -BudgetMs $budgetJ3
            if (-not $r.Ok) { return $null }
            return $r.Bytes
        }.GetNewClosure()
        $script:GwSelfTestJ3WriteInvoked = $false
        $captureJ3 = { param($bytes) $script:GwSelfTestJ3WriteInvoked = $true }
        $failedJ3 = $false
        try {
            Receive-GwTokenFrameAndForward -ReadBytesExact $readJ3Exact -WriteBytes $captureJ3
        } catch {
            $failedJ3 = $true
        }
        if (-not $failedJ3) { $failures.Add('process_stdout_partial_not_classified_failure') }
        if ($script:GwSelfTestJ3WriteInvoked) { $failures.Add('process_stdout_partial_invoked_serial_write') }
        $childJ3.WaitForExit(2000) | Out-Null
        if (-not $childJ3.HasExited) { $failures.Add('process_stdout_partial_child_not_terminated') }
    } finally {
        try { if (-not $childJ3.HasExited) { $childJ3.Kill() } } catch { }
        $childJ3.Dispose()
    }

    # J4. successful process-stdout fixture: child writes exactly a valid synthetic 8-byte zero-payload
    # BRIDGE_READY header and exits.
    $childJ4 = New-GwSelfTestChildProcess -ChildCommand '$s = [Console]::OpenStandardOutput(); $b = [byte[]](0x47,0x4E,0x58,0x33,0x01,0x01,0x00,0x00); $s.Write($b, 0, $b.Length); $s.Flush()'
    try {
        $swJ4 = [System.Diagnostics.Stopwatch]::StartNew()
        $resultJ4 = Read-GwStreamExactBounded -Stream $childJ4.StandardOutput.BaseStream -Process $childJ4 -Count $Script:GwHeaderBytes -Stopwatch $swJ4 -BudgetMs 3000
        if (-not $resultJ4.Ok) {
            $failures.Add('process_stdout_success_fixture_failed')
        } else {
            $parsedJ4 = Test-GwFrameHeader -Header $resultJ4.Bytes
            if (-not $parsedJ4.Ok -or $parsedJ4.Type -ne $Script:GwMsgBridgeReady -or $parsedJ4.Length -ne 0) {
                $failures.Add('process_stdout_success_fixture_wrong_bytes')
            }
        }
    } finally {
        try { if (-not $childJ4.HasExited) { $childJ4.Kill() } } catch { }
        $childJ4.WaitForExit(2000) | Out-Null
        $childJ4.Dispose()
    }

    # J5. shared TOKEN_FRAME budget fixture: child writes a synthetic TOKEN_FRAME header (type=TOKEN_FRAME,
    # length=1) within budget, then delays the 1-byte payload beyond the SAME total budget. Proves the header
    # and payload reads do not each receive a separate full timeout window.
    $childJ5 = New-GwSelfTestChildProcess -ChildCommand '$s = [Console]::OpenStandardOutput(); $h = [byte[]](0x47,0x4E,0x58,0x33,0x01,0x02,0x00,0x01); $s.Write($h, 0, $h.Length); $s.Flush(); Start-Sleep -Milliseconds 3000; $p = [byte[]](0x41); $s.Write($p, 0, $p.Length); $s.Flush()'
    try {
        $swJ5 = [System.Diagnostics.Stopwatch]::StartNew()
        $budgetJ5 = 300
        $readJ5Exact = {
            param($count)
            $r = Read-GwStreamExactBounded -Stream $childJ5.StandardOutput.BaseStream -Process $childJ5 -Count $count -Stopwatch $swJ5 -BudgetMs $budgetJ5
            if (-not $r.Ok) { return $null }
            return $r.Bytes
        }.GetNewClosure()
        $script:GwSelfTestJ5WriteInvoked = $false
        $captureJ5 = { param($bytes) $script:GwSelfTestJ5WriteInvoked = $true }
        $failedJ5 = $false
        try {
            Receive-GwTokenFrameAndForward -ReadBytesExact $readJ5Exact -WriteBytes $captureJ5
        } catch {
            $failedJ5 = $true
        }
        if (-not $failedJ5) { $failures.Add('process_stdout_shared_deadline_not_classified_failure') }
        if ($script:GwSelfTestJ5WriteInvoked) { $failures.Add('process_stdout_shared_deadline_invoked_serial_write') }
    } finally {
        try { if (-not $childJ5.HasExited) { $childJ5.Kill() } } catch { }
        $childJ5.WaitForExit(2000) | Out-Null
        $childJ5.Dispose()
    }

    # J6. post-staged decision-read timeout, using a REAL process fixture: proves the decision read itself
    # fails closed via the same hard-bounded mechanism against an actual Process.StandardOutput.BaseStream.
    # The structural absence of any New-GwFrame -Type ...ProvisionAbort call site inside Invoke-GwLiveBridge
    # (proven separately, unaffected by this correction) is what guarantees no bridge-originated ABORT results
    # from this failure.
    $childJ6 = New-GwSelfTestChildProcess -ChildCommand 'Start-Sleep -Milliseconds 3000'
    try {
        $swJ6 = [System.Diagnostics.Stopwatch]::StartNew()
        $resultJ6 = Read-GwStreamExactBounded -Stream $childJ6.StandardOutput.BaseStream -Process $childJ6 -Count $Script:GwHeaderBytes -Stopwatch $swJ6 -BudgetMs 300
        if ($resultJ6.Ok) { $failures.Add('process_stdout_decision_timeout_not_classified') }
    } finally {
        try { if (-not $childJ6.HasExited) { $childJ6.Kill() } } catch { }
        $childJ6.WaitForExit(2000) | Out-Null
        $childJ6.Dispose()
    }

    # 11. -ProtocolTimeoutSeconds validation: in range accepted, out of range rejected -- real structural
    # ordering (>15 and <1 both rejected; the firmware-safety-margin boundary itself accepted).
    if (-not (Test-GwProtocolTimeoutSecondsValid -Seconds 15)) { $failures.Add('protocol_timeout_boundary_15_rejected') }
    if (Test-GwProtocolTimeoutSecondsValid -Seconds 16) { $failures.Add('protocol_timeout_16_accepted') }
    if (Test-GwProtocolTimeoutSecondsValid -Seconds 999) { $failures.Add('protocol_timeout_999_accepted') }
    if (Test-GwProtocolTimeoutSecondsValid -Seconds 0) { $failures.Add('protocol_timeout_0_accepted') }
    if (-not (Test-GwProtocolTimeoutSecondsValid -Seconds 1)) { $failures.Add('protocol_timeout_boundary_1_rejected') }

    return $failures.ToArray()
}

# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
if ($SelfTest) {
    $failures = Invoke-GwSelfTest
    if ($failures.Count -eq 0) {
        Write-Output '[M3A_BRIDGE] selftest: PASS'
        exit 0
    }
    Write-Output "[M3A_BRIDGE] selftest: FAIL ($($failures -join ', '))"
    exit 1
}

if (-not $LiveAuthorized) {
    Write-Error '[M3A_BRIDGE] live mode requires -LiveAuthorized'
    exit 2
}
if ([string]::IsNullOrWhiteSpace($ComPort)) {
    Write-Error '[M3A_BRIDGE] live mode requires a non-empty -ComPort'
    exit 2
}
if ([string]::IsNullOrWhiteSpace($SshTarget)) {
    Write-Error '[M3A_BRIDGE] live mode requires a non-empty -SshTarget'
    exit 2
}
if ($ComPort -notmatch '^COM[0-9]{1,3}$') {
    Write-Error '[M3A_BRIDGE] -ComPort has an unexpected shape'
    exit 2
}
if ($SshTarget -notmatch '^[A-Za-z0-9_.@:-]{1,255}$') {
    Write-Error '[M3A_BRIDGE] -SshTarget has an unexpected shape'
    exit 2
}
if (-not (Test-GwProtocolTimeoutSecondsValid -Seconds $ProtocolTimeoutSeconds)) {
    Write-Error '[M3A_BRIDGE] -ProtocolTimeoutSeconds must be between 1 and 15'
    exit 2
}

exit (Invoke-GwLiveBridge -ComPort $ComPort -SshTarget $SshTarget -BaudRate $BaudRate `
    -DeviceReadyTimeoutSeconds $DeviceReadyTimeoutSeconds -ProtocolTimeoutSeconds $ProtocolTimeoutSeconds)
