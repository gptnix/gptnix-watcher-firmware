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
       SAME deadline -- see D3). Uses BeginRead/EndRead + AsyncWaitHandle.WaitOne(remaining) because a
       redirected child-process StandardOutput pipe stream does not support Stream.ReadTimeout. Classifies
       timeout/EOF/success without ever including read bytes in the returned failure. On timeout, this
       function itself never calls EndRead() on the abandoned IAsyncResult and never exposes the local
       (possibly partially-filled) buffer to the caller -- it is scrubbed and left to be garbage collected. A
       timed-out read can therefore never later hand bytes to any code that would forward them; the CALLER is
       still responsible for disposing/closing the underlying stream/process so no abandoned async operation
       remains outstanding against a transport this bridge still trusts. #>
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
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
        $asyncResult = $Stream.BeginRead($buf, $got, $Count - $got, $null, $null)
        $signaled = $asyncResult.AsyncWaitHandle.WaitOne($remainingMs)
        if (-not $signaled) {
            [Array]::Clear($buf, 0, $buf.Length)
            return @{ Ok = $false; Reason = 'timeout' }
        }
        $n = $Stream.EndRead($asyncResult)
        if ($n -le 0) {
            [Array]::Clear($buf, 0, $buf.Length)
            return @{ Ok = $false; Reason = 'eof' }
        }
        $got += $n
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
            $result = Read-GwStreamExactBounded -Stream $outStream -Count $count -Stopwatch $tokenFrameStopwatch -BudgetMs $tokenFrameBudgetMs
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
            $result = Read-GwStreamExactBounded -Stream $outStream -Count $count -Stopwatch $decisionStopwatch -BudgetMs $decisionBudgetMs
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

    # 9. Read-GwStreamExactBounded: an expired/zero-remaining deadline against a stream that never delivers
    # any bytes returns a classified timeout failure -- never blocks past its budget. Uses an in-process
    # anonymous pipe (no COM port, no SSH, no network socket) whose server side never writes, so the client
    # side's read genuinely has to wait, proving real bounded behavior rather than a synthetic short-circuit.
    $pipeServerA = New-Object System.IO.Pipes.AnonymousPipeServerStream([System.IO.Pipes.PipeDirection]::Out)
    $pipeClientA = New-Object System.IO.Pipes.AnonymousPipeClientStream([System.IO.Pipes.PipeDirection]::In, $pipeServerA.ClientSafePipeHandle)
    try {
        $swA = [System.Diagnostics.Stopwatch]::StartNew()
        $resultA = Read-GwStreamExactBounded -Stream $pipeClientA -Count $Script:GwHeaderBytes -Stopwatch $swA -BudgetMs 300
        if ($resultA.Ok) {
            $failures.Add('bounded_read_timeout_not_classified')
        } elseif ($resultA.Reason -ne 'timeout') {
            $failures.Add('bounded_read_timeout_wrong_reason')
        }
    } finally {
        $pipeClientA.Dispose()
        $pipeServerA.Dispose()
    }

    # 10. partial backend frame (fewer bytes than a full header) + expired deadline: still a classified
    # failure, and Receive-GwTokenFrameAndForward must never invoke the serial-write callback on this path.
    $pipeServerB = New-Object System.IO.Pipes.AnonymousPipeServerStream([System.IO.Pipes.PipeDirection]::Out)
    $pipeClientB = New-Object System.IO.Pipes.AnonymousPipeClientStream([System.IO.Pipes.PipeDirection]::In, $pipeServerB.ClientSafePipeHandle)
    try {
        $partialHeader = [byte[]](0x47, 0x4E, 0x58, 0x33) # magic only -- never the rest of the 8-byte header
        $pipeServerB.Write($partialHeader, 0, $partialHeader.Length)
        $pipeServerB.Flush()

        $swB = [System.Diagnostics.Stopwatch]::StartNew()
        $budgetB = 300
        $readPartialExact = {
            param($count)
            $r = Read-GwStreamExactBounded -Stream $pipeClientB -Count $count -Stopwatch $swB -BudgetMs $budgetB
            if (-not $r.Ok) { return $null }
            return $r.Bytes
        }.GetNewClosure()

        $script:GwSelfTestPartialWriteInvoked = $false
        $captureWritePartial = { param($bytes) $script:GwSelfTestPartialWriteInvoked = $true }

        $failedClosed = $false
        try {
            Receive-GwTokenFrameAndForward -ReadBytesExact $readPartialExact -WriteBytes $captureWritePartial
        } catch {
            $failedClosed = $true
        }
        if (-not $failedClosed) { $failures.Add('partial_frame_timeout_not_classified_failure') }
        if ($script:GwSelfTestPartialWriteInvoked) { $failures.Add('timeout_read_invoked_serial_write') }
    } finally {
        $pipeClientB.Dispose()
        $pipeServerB.Dispose()
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
