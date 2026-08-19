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

# Physically-derived noise-tolerance ceiling for device-frame resynchronization (see
# Read-GwFrameHeaderResynchronized) -- NOT an arbitrary retry budget. It is the maximum number of bytes the
# pinned physical transport (115200 baud, 8N1 = 10 line bits per payload byte) can physically deliver within
# the maximum allowed protocol wall-clock budget (ProtocolTimeoutSeconds max = 15s):
#   115200 / 10 * 15 = 172800 bytes
# The caller-owned wall-clock $Deadline passed into Read-GwFrameHeaderResynchronized remains the sole
# authoritative timeout in every case; this byte ceiling is only a secondary hard bound, and by construction it
# can never be smaller than what the wire could legitimately have queued (stale console/log backlog) in that
# same window -- e.g. RX backlog accumulated while this bridge was blocked waiting on the backend TOKEN_FRAME.
$Script:GwMaxResyncNoiseBytes = 172800

# The real, unmodified exit-status contract Invoke-GwLiveBridge has always returned: 0 for both the COMMIT
# and ABORT success/decision paths, 2 for each of its three classified failure paths (device_ready timeout,
# backend_token_frame invalid, backend_decision malformed). Defined once, up front, so both the production
# top-level launcher and the -SelfTest dynamic regression cases (via the shared Resolve-GwLiveBridgeExitCode
# helper below) validate against the exact same set -- never an invented or duplicated one.
$Script:GwLiveBridgeExitCodes = @(0, 2)

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

function Read-GwFrameHeaderResynchronized {
    <# Bounded, noise-tolerant frame-header scanner for control frames arriving on a UART also used for
       firmware console/log output -- generalizes Wait-GwBridgeReady's proven magic-scan technique into a
       reusable primitive that returns the parsed header instead of a bare boolean, without changing
       Wait-GwBridgeReady's own behavior/signature/call site at all. $ReadByte is a scriptblock returning one
       byte (0-255) or $null on a bounded per-call timeout/no-data, exactly like Wait-GwBridgeReady's own
       contract. $Deadline is ONE caller-owned wall-clock deadline shared across both the magic scan and the
       remaining-header read -- never a fresh deadline per phase. Once a 4-byte magic alignment is found, this
       function COMMITS to it: it reads the remaining 4 header bytes and returns whatever Test-GwFrameHeader
       says (even a structurally-valid-but-wrong-type/version/payload rejection) -- it never resumes scanning
       past an aligned magic, which would otherwise risk silently skipping a genuine protocol-ordering
       violation. Never stringifies/logs/stores scanned noise bytes -- only counts them against a fixed bound.
       Returns @{Ok;Type;Length;Reason;Header} on a fully read+parsed header, or @{Ok=$false;Reason=<classified
       string>} on scan_limit/timeout/header_timeout -- the same classified-string discipline as
       Test-GwFrameHeader itself. #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ReadByte,
        [Parameter(Mandatory = $true)][datetime]$Deadline,
        [int]$MaxNoiseBytes = $Script:GwMaxResyncNoiseBytes
    )
    $window = New-Object System.Collections.Generic.Queue[byte]
    $scanned = 0
    while ((Get-Date) -lt $Deadline) {
        if ($scanned -gt $MaxNoiseBytes) {
            return @{ Ok = $false; Reason = 'scan_limit' }
        }
        $b = & $ReadByte
        if ($null -eq $b) { continue }
        $window.Enqueue([byte]$b)
        while ($window.Count -gt 4) { [void]$window.Dequeue() }
        $scanned += 1
        if ($window.Count -eq 4 -and (Test-GwByteArrayEqual -A $window.ToArray() -B $Script:GwMagic)) {
            # Magic aligned -- committed. Read exactly the remaining 4 header bytes within the SAME deadline;
            # never resume scanning after this point regardless of what the remaining bytes turn out to be.
            $rest = New-Object byte[] 4
            $got = 0
            while ($got -lt 4) {
                if ((Get-Date) -ge $Deadline) {
                    return @{ Ok = $false; Reason = 'header_timeout' }
                }
                $rb = & $ReadByte
                if ($null -eq $rb) { continue }
                $rest[$got] = [byte]$rb
                $got += 1
            }
            $header = New-Object byte[] $Script:GwHeaderBytes
            [Array]::Copy($window.ToArray(), 0, $header, 0, 4)
            [Array]::Copy($rest, 0, $header, 4, 4)
            $parsed = Test-GwFrameHeader -Header $header
            return @{ Ok = $parsed.Ok; Type = $parsed.Type; Length = $parsed.Length; Reason = $parsed.Reason; Header = $header }
        }
    }
    return @{ Ok = $false; Reason = 'timeout' }
}

function Receive-GwTokenFrameAndForward {
    <# Reads exactly one TOKEN_FRAME via $ReadBytesExact (backend fd3 stream),
       forwards the exact raw frame bytes to $WriteBytes (serial) unmodified,
       and clears the local byte[] copy in a finally block immediately after
       the write. Never converts the payload to a String, never prints it.

       -BeforeWrite (M3A TOKEN_STAGED RX-backlog fix): an optional hook invoked EXACTLY ONCE, after the backend
       TOKEN_FRAME has been fully read and validated but strictly BEFORE the first byte of that frame is written
       via $WriteBytes. It receives no token bytes at all -- it exists solely so the live caller can discard a
       stale device RX backlog (firmware console/log output that queued up while this function was waiting on
       the backend) immediately before writing TOKEN_FRAME. Never before validation (which could otherwise
       discard bytes belonging to a real in-flight exchange) and never after the write begins (which could race
       the device's own read of what this function just wrote). If -BeforeWrite throws, $WriteBytes is never
       called and the failure is re-thrown as one fixed classified string -- never the caller's raw exception,
       in case it were ever to mention transport internals. #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ReadBytesExact, # (count) -> byte[] or $null
        [scriptblock]$BeforeWrite,                                  # () -> void, invoked once before WriteBytes
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
        if ($BeforeWrite) {
            try {
                & $BeforeWrite
            } catch {
                throw 'gw_token_frame_rx_barrier_failed'
            }
        }
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
       success.

       Resynchronizing (M3A TOKEN_STAGED serial-resync fix): the device UART also carries firmware
       console/log output, so a real TOKEN_STAGED frame can legitimately be preceded by non-protocol bytes
       (e.g. the firmware's own "[V2_WATCHER_PROVISION] bridge: ready" log line, or another background
       task's asynchronous log output) -- see Read-GwFrameHeaderResynchronized. This reads byte-by-byte via
       $ReadByte (identical per-call contract to Wait-GwBridgeReady's own reader) within ONE caller-owned
       $Deadline, exactly like BRIDGE_READY's own proven tolerance, instead of assuming byte 0 of the next
       exact-count read is already the frame. #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ReadByte,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )
    $parsed = Read-GwFrameHeaderResynchronized -ReadByte $ReadByte -Deadline $Deadline
    if (-not $parsed.Ok -or $parsed.Type -ne $Script:GwMsgTokenStaged -or $parsed.Length -ne 0) {
        throw "gw_token_staged_not_confirmed: $($parsed.Reason)"
    }
    # Exact-forward correction: return the actual validated device header bytes -- never a bare boolean --
    # so the caller (Invoke-GwLiveBridge) forwards the SAME bytes the device sent, never a reconstructed frame.
    return [byte[]]$parsed.Header
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

# Canonical single owner for invoking a live-bridge-shaped scriptblock and validating its captured
# success-stream result against the real production exit contract $Script:GwLiveBridgeExitCodes (0, 2).
# Used by BOTH the top-level production launcher (invoking the real Invoke-GwLiveBridge) and this file's own
# -SelfTest dynamic regression cases below (invoking synthetic scriptblocks) -- so a runtime PowerShell
# stream/exit-semantics defect in one path is provably a defect in the other; there is no duplicated or
# parallel validation logic anywhere else to drift out of sync. The classified Write-Error on the malformed
# path is explicitly -ErrorAction Continue: this script sets $ErrorActionPreference = 'Stop' at top scope, so
# an unqualified Write-Error here would itself become a terminating error and the `return 2` immediately
# below it would never execute -- the exact class of unreliable runtime behavior this whole correction exists
# to catch, not something to accidentally reintroduce in new code.
function Resolve-GwLiveBridgeExitCode {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Invoke
    )
    $result = & $Invoke
    if ($result -isnot [int] -or ($Script:GwLiveBridgeExitCodes -notcontains $result)) {
        Write-Error -Message '[M3A_BRIDGE] live_result_malformed: unexpected non-integer or out-of-contract status' -ErrorAction Continue
        return 2
    }
    return $result
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

        # Live diagnostics use Write-Host, never Write-Output: Write-Host writes straight to the console host,
        # outside the PowerShell success/pipeline stream, so it can never be captured by `exit (FunctionCall)`,
        # `$var = FunctionCall`, or any other pipeline/capture construct -- it always prints live, regardless
        # of how this function's own `return` status is later consumed by its caller. See the top-level entry
        # point below for the matching half of this fix (the exit-status capture).
        Write-Host '[M3A_BRIDGE] waiting for device BRIDGE_READY before starting backend session'
        $found = Wait-GwBridgeReady -ReadByte $readDeviceByte -TimeoutSeconds $DeviceReadyTimeoutSeconds
        if (-not $found) {
            Write-Error '[M3A_BRIDGE] device_ready: timeout -- refusing to start backend session'
            return 2
        }
        Write-Host '[M3A_BRIDGE] device_ready: true'

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

        # RX backlog barrier (M3A TOKEN_STAGED RX-backlog fix): passed as Receive-GwTokenFrameAndForward's
        # -BeforeWrite hook, so it runs exactly once, strictly after the backend TOKEN_FRAME has been fully
        # validated and strictly before its first byte is written to the device -- see that function's own
        # contract. The device cannot legally emit TOKEN_STAGED before it has received a valid TOKEN_FRAME, so
        # this discard can never delete a legitimate current-exchange TOKEN_STAGED; it only clears stale
        # firmware console/log output that queued up in the Windows RX buffer while this function was blocked
        # waiting on the backend. This is the ONE live DiscardInBuffer call site in the whole bridge -- never
        # DiscardOutBuffer, never a Close/Open of the port, never a DTR/RTS toggle.
        $discardDeviceInput = {
            $port.DiscardInBuffer()
        }.GetNewClosure()

        try {
            Receive-GwTokenFrameAndForward -ReadBytesExact $readBackendExact -BeforeWrite $discardDeviceInput -WriteBytes $writeSerialBytes
        } catch {
            if ($_.Exception.Message -eq 'gw_token_frame_rx_barrier_failed') {
                # The RX barrier itself threw -- classify distinctly from an ordinary backend/frame failure so a
                # future diagnostic can tell the two apart. No serial write occurred (see the barrier's own
                # contract); the outer finally tears down the backend transport defensively either way.
                Write-Error '[M3A_BRIDGE] device_rx_barrier: failed'
            } else {
                # Bounded backend read failed (timeout/EOF) or the frame was malformed -- no serial write occurred
                # (see the comment above). Terminate the backend transport now so no abandoned async read can ever
                # later deliver a late TOKEN_FRAME while the device may already have left its raw provisioning
                # window; the outer finally also tears this down defensively.
                Write-Error '[M3A_BRIDGE] backend_token_frame: bounded read failed or frame invalid'
            }
            return 2
        }

        # M3A TOKEN_STAGED serial-resync fix: reuse the SAME per-byte device reader already proven for
        # BRIDGE_READY ($readDeviceByte, defined above) -- one serial owner, one read contract -- under one
        # fresh wall-clock deadline for this exchange (same $ProtocolTimeoutSeconds budget concept the prior
        # exact-count reader used, now shared across both the magic scan and the remaining-header read).
        $tokenStagedDeadline = (Get-Date).AddSeconds($ProtocolTimeoutSeconds)
        # Exact-forward correction: $stagedFrame IS the validated device header returned by
        # Confirm-GwDeviceTokenStaged -- never a bridge-reconstructed frame. The bridge must forward exactly
        # what the device sent, never fabricate a fresh TOKEN_STAGED of its own.
        $stagedFrame = Confirm-GwDeviceTokenStaged -ReadByte $readDeviceByte -Deadline $tokenStagedDeadline

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
            Write-Host '[M3A_BRIDGE] decision: abort'
            return 0
        }
        Write-Host '[M3A_BRIDGE] decision: commit'

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
            Write-Host '[M3A_BRIDGE] device_ready: true'
        } else {
            Write-Host '[M3A_BRIDGE] device_ready: timeout'
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
    # fixture -- the bridge never fabricates it. Uses the new byte-by-byte -ReadByte/-Deadline signature
    # (M3A TOKEN_STAGED serial-resync fix) instead of the retired -ReadBytesExact positional reader.
    $wrongFrame = New-GwFrame -Type $Script:GwMsgProvisionAbort -Payload @()
    $wrongState = [pscustomobject]@{ Index = 0 }
    $readWrong = {
        if ($wrongState.Index -ge $wrongFrame.Length) { return $null }
        $b = $wrongFrame[$wrongState.Index]
        $wrongState.Index++
        return $b
    }.GetNewClosure()
    $rejectedWrong = $false
    try {
        Confirm-GwDeviceTokenStaged -ReadByte $readWrong -Deadline ((Get-Date).AddSeconds(2)) | Out-Null
    } catch {
        $rejectedWrong = $true
    }
    if (-not $rejectedWrong) { $failures.Add('token_staged_guard_accepted_wrong_frame') }

    $realStagedFrame = New-GwFrame -Type $Script:GwMsgTokenStaged -Payload @()
    $realState = [pscustomobject]@{ Index = 0 }
    $readReal = {
        if ($realState.Index -ge $realStagedFrame.Length) { return $null }
        $b = $realStagedFrame[$realState.Index]
        $realState.Index++
        return $b
    }.GetNewClosure()
    $acceptedReal = $null
    try {
        $acceptedReal = Confirm-GwDeviceTokenStaged -ReadByte $readReal -Deadline ((Get-Date).AddSeconds(2))
    } catch {
        $acceptedReal = $null
    }
    # Exact-forward correction: Confirm-GwDeviceTokenStaged's OWN return value (not merely the underlying
    # scanner's Header field) must be the exact 8 device bytes -- this is what Invoke-GwLiveBridge actually
    # forwards upstream.
    if ($null -eq $acceptedReal -or $acceptedReal.Length -ne 8 -or -not (Test-GwByteArrayEqual -A $acceptedReal -B $realStagedFrame)) {
        $failures.Add('token_staged_guard_rejected_real_frame_or_bytes_not_exact')
    }

    # 8b. text noise (a realistic firmware console/log line sharing the UART) preceding a real TOKEN_STAGED
    # frame is tolerated, and the returned header is the EXACT device bytes -- never a reconstruction.
    $textNoise = [System.Text.Encoding]::ASCII.GetBytes("[V2_WATCHER_PROVISION] bridge: ready`n")
    $noisyRealFixture = New-Object System.Collections.Generic.List[byte]
    $noisyRealFixture.AddRange([byte[]]$textNoise)
    $noisyRealFixture.AddRange([byte[]]$realStagedFrame)
    $noisyRealArray = $noisyRealFixture.ToArray()
    $noisyRealState = [pscustomobject]@{ Index = 0 }
    $readNoisyReal = {
        if ($noisyRealState.Index -ge $noisyRealArray.Length) { return $null }
        $b = $noisyRealArray[$noisyRealState.Index]
        $noisyRealState.Index++
        return $b
    }.GetNewClosure()
    $noisyRealResult = Read-GwFrameHeaderResynchronized -ReadByte $readNoisyReal -Deadline ((Get-Date).AddSeconds(2))
    if (-not $noisyRealResult.Ok -or $noisyRealResult.Type -ne $Script:GwMsgTokenStaged -or $noisyRealResult.Length -ne 0) {
        $failures.Add('resync_text_noise_not_tolerated')
    }
    if (-not (Test-GwByteArrayEqual -A $noisyRealResult.Header -B $realStagedFrame)) {
        $failures.Add('resync_returned_header_not_exact_device_bytes')
    }

    # 8c. arbitrary binary non-GNX3 noise preceding a real TOKEN_STAGED frame is tolerated.
    $binNoise = [byte[]](0x00, 0xFF, 0x10, 0x20, 0x7A, 0x99)
    $binNoisyFixture = New-Object System.Collections.Generic.List[byte]
    $binNoisyFixture.AddRange($binNoise)
    $binNoisyFixture.AddRange([byte[]]$realStagedFrame)
    $binNoisyArray = $binNoisyFixture.ToArray()
    $binNoisyState = [pscustomobject]@{ Index = 0 }
    $readBinNoisy = {
        if ($binNoisyState.Index -ge $binNoisyArray.Length) { return $null }
        $b = $binNoisyArray[$binNoisyState.Index]
        $binNoisyState.Index++
        return $b
    }.GetNewClosure()
    $binNoisyResult = Read-GwFrameHeaderResynchronized -ReadByte $readBinNoisy -Deadline ((Get-Date).AddSeconds(2))
    if (-not $binNoisyResult.Ok -or $binNoisyResult.Type -ne $Script:GwMsgTokenStaged) {
        $failures.Add('resync_binary_noise_not_tolerated')
    }

    # 8d. reads split byte-by-byte with a $null "no data yet" gap before every byte (matching a real
    # per-call device-port read timeout), PLUS a genuine partial-magic false start ("G","N" then a byte
    # that breaks the match) before the real magic -- the rolling window must not falsely trigger on the
    # false start and must still resynchronize correctly across the interleaved gaps.
    $falseStartPrefix = [byte[]](0x47, 0x4E, 0x00, 0x41, 0x42)
    $splitFixtureBytes = New-Object System.Collections.Generic.List[byte]
    $splitFixtureBytes.AddRange($falseStartPrefix)
    $splitFixtureBytes.AddRange([byte[]]$realStagedFrame)
    $splitArray = $splitFixtureBytes.ToArray()
    $splitState = [pscustomobject]@{ Index = 0; EmitNull = $true }
    $readSplit = {
        if ($splitState.EmitNull) {
            $splitState.EmitNull = $false
            return $null
        }
        if ($splitState.Index -ge $splitArray.Length) { return $null }
        $b = $splitArray[$splitState.Index]
        $splitState.Index++
        $splitState.EmitNull = $true
        return $b
    }.GetNewClosure()
    $splitResult = Read-GwFrameHeaderResynchronized -ReadByte $readSplit -Deadline ((Get-Date).AddSeconds(2))
    if (-not $splitResult.Ok -or $splitResult.Type -ne $Script:GwMsgTokenStaged) {
        $failures.Add('resync_split_reads_or_false_start_not_tolerated')
    }

    # 8e. bounded scan limit: a stream of pure non-magic noise beyond an explicit small test-local
    # -MaxNoiseBytes fails closed with a classified reason instead of scanning forever. This fixture proves
    # generic byte-bound scan_limit semantics, not real-world throughput -- it deliberately does NOT scale
    # against the live $Script:GwMaxResyncNoiseBytes canonical default (172800): scanning a fixture that size
    # is >172k per-byte closure invocations, which on the real Windows CI runner can exceed a short bounded
    # deadline before the byte ceiling itself is ever reached, turning this into an accidental timing test
    # instead of a scan_limit test. Same small-explicit-bound pattern already proven by fixture K5 below.
    $overLimitTestMaxNoiseBytes = 32
    $overLimitNoise = New-Object byte[] ($overLimitTestMaxNoiseBytes + 16)
    for ($i = 0; $i -lt $overLimitNoise.Length; $i++) { $overLimitNoise[$i] = 0x58 }
    $overLimitState = [pscustomobject]@{ Index = 0 }
    $readOverLimit = {
        if ($overLimitState.Index -ge $overLimitNoise.Length) { return $null }
        $b = $overLimitNoise[$overLimitState.Index]
        $overLimitState.Index++
        return $b
    }.GetNewClosure()
    $overLimitResult = Read-GwFrameHeaderResynchronized -ReadByte $readOverLimit -Deadline ((Get-Date).AddSeconds(2)) -MaxNoiseBytes $overLimitTestMaxNoiseBytes
    if ($overLimitResult.Ok -or $overLimitResult.Reason -ne 'scan_limit') {
        $failures.Add('resync_scan_limit_not_enforced')
    }

    # 8f. deadline expiry before magic is ever found fails closed with a classified reason, never silently.
    $readNeverMagic = { return [byte]0x58 }
    $timeoutResult = Read-GwFrameHeaderResynchronized -ReadByte $readNeverMagic -Deadline ((Get-Date).AddMilliseconds(150)) -MaxNoiseBytes 1000000
    if ($timeoutResult.Ok -or $timeoutResult.Reason -ne 'timeout') {
        $failures.Add('resync_timeout_not_enforced')
    }

    # 8g. magic found but the remaining 4 header bytes arrive only partially (then never) before the deadline
    # -- fails closed with a distinct classified reason, and never returns a fabricated/partial header as Ok.
    $truncHeaderBytes = New-Object System.Collections.Generic.List[byte]
    $truncHeaderBytes.AddRange([byte[]]$Script:GwMagic)
    $truncHeaderBytes.Add([byte]0x01)
    $truncHeaderArray = $truncHeaderBytes.ToArray()
    $truncHeaderState = [pscustomobject]@{ Index = 0 }
    $readTruncHeader = {
        if ($truncHeaderState.Index -ge $truncHeaderArray.Length) { return $null }
        $b = $truncHeaderArray[$truncHeaderState.Index]
        $truncHeaderState.Index++
        return $b
    }.GetNewClosure()
    $truncHeaderResult = Read-GwFrameHeaderResynchronized -ReadByte $readTruncHeader -Deadline ((Get-Date).AddMilliseconds(150))
    if ($truncHeaderResult.Ok -or $truncHeaderResult.Reason -ne 'header_timeout') {
        $failures.Add('resync_partial_header_not_classified')
    }

    # 8h. magic + wrong version fails closed (Test-GwFrameHeader's own classification, unchanged, propagated
    # through the resync primitive without being reinterpreted or skipped past).
    $wrongVersionHeader = [byte[]]($Script:GwMagic + [byte[]](0x02, $Script:GwMsgTokenStaged, 0x00, 0x00))
    $wrongVersionState = [pscustomobject]@{ Index = 0 }
    $readWrongVersion = {
        if ($wrongVersionState.Index -ge $wrongVersionHeader.Length) { return $null }
        $b = $wrongVersionHeader[$wrongVersionState.Index]
        $wrongVersionState.Index++
        return $b
    }.GetNewClosure()
    $wrongVersionResult = Read-GwFrameHeaderResynchronized -ReadByte $readWrongVersion -Deadline ((Get-Date).AddSeconds(2))
    if ($wrongVersionResult.Ok -or $wrongVersionResult.Reason -ne 'version') {
        $failures.Add('resync_wrong_version_not_rejected')
    }

    # 8i. magic + non-zero payload length on an otherwise-valid TOKEN_STAGED header fails closed -- this
    # business rule lives in Confirm-GwDeviceTokenStaged itself (Test-GwFrameHeader only rejects an
    # oversized length, not a non-zero one for a control frame), so this is exercised at that level, mirroring
    # the existing wrong-type guard above.
    $nonZeroPayloadHeader = [byte[]]($Script:GwMagic + [byte[]]($Script:GwVersion, $Script:GwMsgTokenStaged, 0x00, 0x01))
    $nonZeroState = [pscustomobject]@{ Index = 0 }
    $readNonZeroPayload = {
        if ($nonZeroState.Index -ge $nonZeroPayloadHeader.Length) { return $null }
        $b = $nonZeroPayloadHeader[$nonZeroState.Index]
        $nonZeroState.Index++
        return $b
    }.GetNewClosure()
    $rejectedNonZeroPayload = $false
    try {
        Confirm-GwDeviceTokenStaged -ReadByte $readNonZeroPayload -Deadline ((Get-Date).AddSeconds(2)) | Out-Null
    } catch {
        $rejectedNonZeroPayload = $true
    }
    if (-not $rejectedNonZeroPayload) { $failures.Add('resync_nonzero_payload_not_rejected') }

    # 8j. forwarding ownership: Confirm-GwDeviceTokenStaged itself (the function Invoke-GwLiveBridge actually
    # calls) -- not merely the underlying Read-GwFrameHeaderResynchronized scanner exercised by 8b above --
    # returns the exact device header bytes even when the frame is preceded by realistic UART noise. This
    # closes the exact PR #5 architect-review gap: a green test on the scanner's own Header field did not prove
    # Confirm-GwDeviceTokenStaged's own return value (what Invoke-GwLiveBridge actually receives and forwards
    # upstream) was the same exact bytes rather than a bridge-reconstructed frame.
    $ownershipState = [pscustomobject]@{ Index = 0 }
    $readOwnership = {
        if ($ownershipState.Index -ge $noisyRealArray.Length) { return $null }
        $b = $noisyRealArray[$ownershipState.Index]
        $ownershipState.Index++
        return $b
    }.GetNewClosure()
    $ownershipResult = $null
    try {
        $ownershipResult = Confirm-GwDeviceTokenStaged -ReadByte $readOwnership -Deadline ((Get-Date).AddSeconds(2))
    } catch {
        $ownershipResult = $null
    }
    if ($null -eq $ownershipResult -or $ownershipResult.Length -ne 8 -or -not (Test-GwByteArrayEqual -A $ownershipResult -B $realStagedFrame)) {
        $failures.Add('confirm_token_staged_return_not_exact_device_bytes')
    }

    # K1-K5 (M3A TOKEN_STAGED RX-backlog fix): the -BeforeWrite RX barrier hook on
    # Receive-GwTokenFrameAndForward, and the physically-derived resync ceiling, proven purely offline against
    # synthetic in-memory fixtures -- never COM/SSH/network.

    # K1. barrier ordering happy path: a valid synthetic backend TOKEN_FRAME proves the exact call order
    # READ_VALIDATED -> BARRIER -> WRITE, that the barrier runs exactly once, and that WriteBytes receives the
    # untouched original frame bytes -- binary fixture bytes only, never stringified.
    $k1Payload = [byte[]](0x01, 0x02, 0x03, 0x04)
    $k1Frame = New-GwFrame -Type $Script:GwMsgTokenFrame -Payload $k1Payload
    $k1State = [pscustomobject]@{ Index = 0 }
    $k1ReadExact = {
        param($count)
        if ($k1State.Index + $count -gt $k1Frame.Length) { return $null }
        $slice = $k1Frame[$k1State.Index..($k1State.Index + $count - 1)]
        $k1State.Index += $count
        return $slice
    }.GetNewClosure()
    $k1Track = [pscustomobject]@{ Order = (New-Object System.Collections.Generic.List[string]); BarrierCalls = 0; WriteCalls = 0; Written = $null }
    $k1Barrier = {
        $k1Track.BarrierCalls++
        $k1Track.Order.Add('BARRIER')
    }.GetNewClosure()
    $k1Write = {
        param($bytes)
        $k1Track.WriteCalls++
        $k1Track.Order.Add('WRITE')
        # Snapshot/clone at callback time: Receive-GwTokenFrameAndForward's own `finally` zeroizes its
        # internal $frame buffer (the SAME underlying array $bytes references here) immediately after this
        # callback returns -- correct, unchanged production behavior. A bare reference-cast would observe
        # that zeroized state by the time this fixture asserts equality below; an independent copy does not.
        $k1Track.Written = [byte[]]($bytes.Clone())
    }.GetNewClosure()
    Receive-GwTokenFrameAndForward -ReadBytesExact $k1ReadExact -BeforeWrite $k1Barrier -WriteBytes $k1Write
    if ($k1Track.BarrierCalls -ne 1) { $failures.Add('rx_barrier_call_count_not_one') }
    if ($k1Track.WriteCalls -ne 1) { $failures.Add('rx_barrier_write_call_count_not_one') }
    if ($k1Track.Order.Count -lt 2 -or $k1Track.Order[0] -ne 'BARRIER' -or $k1Track.Order[1] -ne 'WRITE') {
        $failures.Add('rx_barrier_not_before_write')
    }
    if ($null -eq $k1Track.Written -or -not (Test-GwByteArrayEqual -A $k1Track.Written -B $k1Frame)) {
        $failures.Add('rx_barrier_write_frame_mismatch')
    }

    # K2. a malformed backend TOKEN_FRAME (bad magic) never reaches the RX barrier or the serial write.
    $k2BadFrame = [byte[]](0x00, 0x00, 0x00, 0x00, $Script:GwVersion, $Script:GwMsgTokenFrame, 0x00, 0x01, 0x41)
    $k2State = [pscustomobject]@{ Index = 0 }
    $k2ReadExact = {
        param($count)
        if ($k2State.Index + $count -gt $k2BadFrame.Length) { return $null }
        $slice = $k2BadFrame[$k2State.Index..($k2State.Index + $count - 1)]
        $k2State.Index += $count
        return $slice
    }.GetNewClosure()
    $k2Track = [pscustomobject]@{ BarrierCalls = 0; WriteCalls = 0 }
    $k2Barrier = { $k2Track.BarrierCalls++ }.GetNewClosure()
    $k2Write = { param($bytes) $k2Track.WriteCalls++ }.GetNewClosure()
    $k2Failed = $false
    try {
        Receive-GwTokenFrameAndForward -ReadBytesExact $k2ReadExact -BeforeWrite $k2Barrier -WriteBytes $k2Write
    } catch {
        $k2Failed = $true
    }
    if (-not $k2Failed) { $failures.Add('rx_barrier_malformed_frame_not_rejected') }
    if ($k2Track.BarrierCalls -ne 0) { $failures.Add('rx_barrier_ran_on_malformed_frame') }
    if ($k2Track.WriteCalls -ne 0) { $failures.Add('rx_barrier_wrote_on_malformed_frame') }

    # K3. backend timeout/EOF (ReadBytesExact returns $null) never reaches the RX barrier or the serial write.
    $k3ReadExact = { param($count) return $null }.GetNewClosure()
    $k3Track = [pscustomobject]@{ BarrierCalls = 0; WriteCalls = 0 }
    $k3Barrier = { $k3Track.BarrierCalls++ }.GetNewClosure()
    $k3Write = { param($bytes) $k3Track.WriteCalls++ }.GetNewClosure()
    $k3Failed = $false
    try {
        Receive-GwTokenFrameAndForward -ReadBytesExact $k3ReadExact -BeforeWrite $k3Barrier -WriteBytes $k3Write
    } catch {
        $k3Failed = $true
    }
    if (-not $k3Failed) { $failures.Add('rx_barrier_backend_timeout_not_rejected') }
    if ($k3Track.BarrierCalls -ne 0) { $failures.Add('rx_barrier_ran_on_backend_timeout') }
    if ($k3Track.WriteCalls -ne 0) { $failures.Add('rx_barrier_wrote_on_backend_timeout') }

    # K4. if the RX barrier itself throws, the serial write must never occur and the failure must be classified
    # as gw_token_frame_rx_barrier_failed -- never the caller's raw exception object/message.
    $k4Payload = [byte[]](0x05, 0x06)
    $k4Frame = New-GwFrame -Type $Script:GwMsgTokenFrame -Payload $k4Payload
    $k4State = [pscustomobject]@{ Index = 0 }
    $k4ReadExact = {
        param($count)
        if ($k4State.Index + $count -gt $k4Frame.Length) { return $null }
        $slice = $k4Frame[$k4State.Index..($k4State.Index + $count - 1)]
        $k4State.Index += $count
        return $slice
    }.GetNewClosure()
    $k4Track = [pscustomobject]@{ WriteCalls = 0 }
    $k4Barrier = { throw 'synthetic_barrier_failure' }.GetNewClosure()
    $k4Write = { param($bytes) $k4Track.WriteCalls++ }.GetNewClosure()
    $k4ThrownMessage = $null
    try {
        Receive-GwTokenFrameAndForward -ReadBytesExact $k4ReadExact -BeforeWrite $k4Barrier -WriteBytes $k4Write
    } catch {
        $k4ThrownMessage = $_.Exception.Message
    }
    if ($k4ThrownMessage -ne 'gw_token_frame_rx_barrier_failed') { $failures.Add('rx_barrier_failure_not_classified') }
    if ($k4Track.WriteCalls -ne 0) { $failures.Add('rx_barrier_failure_still_wrote') }

    # K5. resync boundary semantics proven generically with a small deterministic -MaxNoiseBytes bound (never
    # the full 172800-byte canonical ceiling, to keep this fixture fast) -- the canonical constant itself is
    # verified separately by static fitness (test_watcher_m3a_provision_fitness.py).
    $k5RealFrame = New-GwFrame -Type $Script:GwMsgTokenStaged -Payload @()

    $k5Below = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt 40; $i++) { $k5Below.Add([byte](0x30 + ($i % 10))) } # synthetic non-secret noise, never GNX3
    $k5Below.AddRange([byte[]]$k5RealFrame)
    $k5BelowArray = $k5Below.ToArray()
    $k5BelowState = [pscustomobject]@{ Index = 0 }
    $k5BelowReadByte = {
        if ($k5BelowState.Index -ge $k5BelowArray.Length) { return $null }
        $b = $k5BelowArray[$k5BelowState.Index]
        $k5BelowState.Index++
        return $b
    }.GetNewClosure()
    $k5BelowResult = Read-GwFrameHeaderResynchronized -ReadByte $k5BelowReadByte -Deadline ((Get-Date).AddSeconds(5)) -MaxNoiseBytes 100
    if (-not $k5BelowResult.Ok -or $k5BelowResult.Type -ne $Script:GwMsgTokenStaged) {
        $failures.Add('rx_barrier_resync_below_small_ceiling_rejected')
    }

    $k5Above = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt 200; $i++) { $k5Above.Add([byte](0x30 + ($i % 10))) }
    $k5Above.AddRange([byte[]]$k5RealFrame)
    $k5AboveArray = $k5Above.ToArray()
    $k5AboveState = [pscustomobject]@{ Index = 0 }
    $k5AboveReadByte = {
        if ($k5AboveState.Index -ge $k5AboveArray.Length) { return $null }
        $b = $k5AboveArray[$k5AboveState.Index]
        $k5AboveState.Index++
        return $b
    }.GetNewClosure()
    $k5AboveResult = Read-GwFrameHeaderResynchronized -ReadByte $k5AboveReadByte -Deadline ((Get-Date).AddSeconds(5)) -MaxNoiseBytes 100
    if ($k5AboveResult.Ok -or $k5AboveResult.Reason -ne 'scan_limit') {
        $failures.Add('rx_barrier_resync_above_small_ceiling_accepted')
    }

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

    # L1-L7: dynamic hermetic Windows proof for Resolve-GwLiveBridgeExitCode -- the EXACT SAME function the
    # production top-level launcher calls at the bottom of this file, not a copy or parallel
    # re-implementation. These cases exercise real PowerShell success/Information-stream semantics on the
    # actual pinned runtime (windows-2022's `powershell.exe -File ... -SelfTest`, see
    # .github/workflows/gptnix-firmware-build.yml) -- a static source grep alone previously let this exact
    # class of runtime stream/exit defect ship undetected. No COM, no SSH, no network, no backend, no device.

    # L1. COMMIT synthetic: a Write-Host diagnostic identical in shape to Invoke-GwLiveBridge's own COMMIT
    # line, plus `return 0`. The `6>&1` redirection here is a SelfTest-only observation trick applied to this
    # ONE outer call -- it never touches Resolve-GwLiveBridgeExitCode's own internals, which still capture
    # only the real success stream exactly as production does.
    $l1Raw = Resolve-GwLiveBridgeExitCode -Invoke { Write-Host '[M3A_BRIDGE] decision: commit'; return 0 } 6>&1
    $l1Result = $l1Raw | Where-Object { $_ -is [int] } | Select-Object -Last 1
    $l1Diagnostic = $l1Raw | Where-Object { $_ -isnot [int] }
    if ($l1Result -ne 0) { $failures.Add('live_result_commit_not_zero') }
    if (-not ($l1Diagnostic | Where-Object { "$_" -like '*decision: commit*' })) {
        $failures.Add('live_result_commit_diagnostic_not_observed')
    }

    # L2. ABORT synthetic: same shape, ABORT's own diagnostic and its documented 0 result.
    $l2Raw = Resolve-GwLiveBridgeExitCode -Invoke { Write-Host '[M3A_BRIDGE] decision: abort'; return 0 } 6>&1
    $l2Result = $l2Raw | Where-Object { $_ -is [int] } | Select-Object -Last 1
    $l2Diagnostic = $l2Raw | Where-Object { $_ -isnot [int] }
    if ($l2Result -ne 0) { $failures.Add('live_result_abort_not_zero') }
    if (-not ($l2Diagnostic | Where-Object { "$_" -like '*decision: abort*' })) {
        $failures.Add('live_result_abort_diagnostic_not_observed')
    }

    # L3. FAILURE synthetic: an invoker that returns the real production classified-failure code directly (2)
    # -- proves the pass-through path preserves a valid non-zero result unchanged.
    $l3Result = Resolve-GwLiveBridgeExitCode -Invoke { return 2 }
    if ($l3Result -ne 2) { $failures.Add('live_result_failure_not_preserved') }

    # L4. MALFORMED string: '0' is never [int] -- must fail closed to 2, never coerce to a truthy success.
    $l4Result = Resolve-GwLiveBridgeExitCode -Invoke { return '0' }
    if ($l4Result -ne 2) { $failures.Add('live_result_malformed_string_not_rejected') }

    # L5. MULTI-ELEMENT: the exact original bug class, reproduced on purpose and proven caught. If a future
    # diagnostic inside an invoked scriptblock ever again used Write-Output instead of Write-Host, its text
    # would land on the SAME success stream Resolve-GwLiveBridgeExitCode's own `$result = & $Invoke` reads --
    # producing a 2-element array (the leaked string plus the real 0), which is `-isnot [int]` and must fail
    # closed to 2, never silently become a truthy/zero-like result.
    $l5Result = Resolve-GwLiveBridgeExitCode -Invoke { Write-Output 'unexpected-success-stream-leak'; return 0 }
    if ($l5Result -ne 2) { $failures.Add('live_result_multi_element_not_rejected') }

    # L6. NULL/missing: an invoker that never reaches a `return` at all yields $null on the success stream --
    # must fail closed to 2.
    $l6Result = Resolve-GwLiveBridgeExitCode -Invoke { }
    if ($l6Result -ne 2) { $failures.Add('live_result_null_not_rejected') }

    # L7. STALE: a valid call immediately followed by a malformed one, proving the second call's result is
    # never contaminated by the first call's prior value (each call's $result is function-local; this proves
    # it dynamically rather than only structurally).
    $l7First = Resolve-GwLiveBridgeExitCode -Invoke { return 0 }
    $l7Second = Resolve-GwLiveBridgeExitCode -Invoke { return 'stale-should-not-leak-a-prior-zero' }
    if ($l7First -ne 0) { $failures.Add('live_result_stale_first_call_not_zero') }
    if ($l7Second -ne 2) { $failures.Add('live_result_stale_second_call_contaminated') }

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

# Live-output / exit-status fix: `exit (Invoke-GwLiveBridge ...)` previously forced PowerShell to fully
# evaluate the parenthesized call as one subexpression -- capturing the function's ENTIRE success/pipeline
# stream (every Write-Output call inside it, plus its own `return` value, since `return` and Write-Output
# share that same stream) into a single in-memory collection before anything was ever streamed live to the
# console, and before that collection was coerced to an exit code. Physically reproduced: a synthetic
# `function f { Write-Output 'x'; return 0 }; exit (f)` never prints 'x' at all. Now that every diagnostic
# inside Invoke-GwLiveBridge uses Write-Host (a separate, uncapturable stream -- see above), its success
# stream carries only the final `return` value, so capturing it here is safe and the diagnostics still print
# live regardless. Resolve-GwLiveBridgeExitCode (defined above, alongside Invoke-GwLiveBridge) is the ONE
# owner of the invoke-then-validate step -- the exact same function this file's own -SelfTest dynamic
# regression cases call with synthetic scriptblocks below, so a runtime PowerShell stream/exit-semantics
# regression here would be caught by that dynamic Windows proof, not merely by an unrelated static grep.
$liveExitCode = Resolve-GwLiveBridgeExitCode -Invoke {
    Invoke-GwLiveBridge -ComPort $ComPort -SshTarget $SshTarget -BaudRate $BaudRate `
        -DeviceReadyTimeoutSeconds $DeviceReadyTimeoutSeconds -ProtocolTimeoutSeconds $ProtocolTimeoutSeconds
}
exit $liveExitCode
