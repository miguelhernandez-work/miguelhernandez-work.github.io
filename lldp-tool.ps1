# ChangeLog
# v2.0 - Miguel Hernandez, 2025-12-03: This tool can be executed via .\lldp-tool.ps1 and will show a menu. It allows us to find out what switch port its on. 
#       - TODO: use API key to update netbox, which in turn can update switchport descriptions to allow for much faster tracking down of a host to the switchports.
#       - TODO: Line 176/177 hardcode the value "Intel" to look for eligible NICs to listen for LLDP frames on. This will undoubtedly change to something else in the future, but works for this PoC.
#       - Note: Intel firmware may not expose LLDP frames to the OS, see Intel docs: 
#       - https://edc.intel.com/content/www/us/en/design/products/ethernet/adapters-and-devices-user-guide/firmware-link-layer-discovery-protocol-fw-lldp/
#       - on Dell BIOS > go to NIC Configuration > edit the NIC > check "LLDP Agent" setting, it should be disabled for the OS to be able to receive LLDP frames.
#

function Decode-LLDP {
    param(
        [byte[]]$Bytes,
        [switch]$Verbose
    )

    $i = 0
    $results = [ordered]@{}
    $tlvCount = 0

    while ($i -lt $Bytes.Length) {
        if ($i + 1 -ge $Bytes.Length) { 
            if ($Verbose) { Write-Host "DEBUG: Not enough bytes for TLV header at position $i" }
            break 
        }

        # TLV Header is 2 bytes: 
        # Byte 0: TTTTTTTL (7 bits type in bits 7-1, 1 bit of length in bit 0)
        # Byte 1: LLLLLLLL (8 bits of length)
        $type = ($Bytes[$i] -shr 1) -band 0x7F
        $length = (($Bytes[$i] -band 0x01) -shl 8) -bor $Bytes[$i+1]

        if ($Verbose) { 
            Write-Host "DEBUG: TLV #$($tlvCount): Position=$i, Type=$type, Length=$length, Header=0x$('{0:X2}{1:X2}' -f $Bytes[$i], $Bytes[$i+1])"
        }

        if ($type -eq 0) { 
            if ($Verbose) { Write-Host "DEBUG: End of LLDPDU marker (type=0) found" }
            break 
        }

        # Check bounds before accessing value bytes
        if ($i + 2 + $length -gt $Bytes.Length) { 
            if ($Verbose) { Write-Host "DEBUG: Not enough bytes for TLV value. Need $($i + 2 + $length), have $($Bytes.Length)" }
            break 
        }

        $value = $Bytes[($i+2)..($i+1+$length)]

        if ($Verbose) {
            $valueHex = [System.BitConverter]::ToString($value)
            Write-Host "DEBUG: TLV Value: $valueHex"
        }

        try {
            switch ($type) {
                1 { 
                    # Skip ChassisID
                    if ($Verbose) { Write-Host "  > ChassisID (skipped)" }
                }
                2 { 
                    if ($value.Length -gt 1) {
                        $subtype = $value[0]
                        $data = [System.Text.Encoding]::ASCII.GetString($value[1..($value.Length-1)])
                        $results["PortID"] = $data
                        if ($Verbose) { Write-Host "  > PortID (subtype=$subtype): $data" }
                    }
                }
                3 { 
                    if ($value.Length -ge 2) {
                        $ttl = ($value[0] -shl 8) -bor $value[1]
                        $results["TTL"] = $ttl
                        if ($Verbose) { Write-Host "  > TTL: $ttl seconds" }
                    }
                }
                5 { 
                    $data = [System.Text.Encoding]::ASCII.GetString($value)
                    $results["SystemName"] = $data
                    if ($Verbose) { Write-Host "  > SystemName: $data" }
                }
                6 { 
                    $data = [System.Text.Encoding]::ASCII.GetString($value)
                    $results["SystemDescription"] = $data
                    if ($Verbose) { Write-Host "  > SystemDescription: $data" }
                }
                8 { 
                    $data = [System.Text.Encoding]::ASCII.GetString($value)
                    $results["PortDescription"] = $data
                    if ($Verbose) { Write-Host "  > PortDescription: $data" }
                }
                default {
                    if ($Verbose) { Write-Host "  > Unknown TLV type $type (length=$length)" }
                }
            }
        } catch {
            if ($Verbose) { Write-Host "  > ERROR parsing type $type : $_" }
        }

        $i += 2 + $length
        $tlvCount++
    }

    if ($Verbose) { Write-Host "DEBUG: Parsed $tlvCount TLVs, final position $i / $($Bytes.Length)" }

    return [PSCustomObject]$results
}

function Import-PcapngFile {
    <#
    .SYNOPSIS
        Import LLDP frames from a pcapng file and decode them
    #>
    param(
        [string]$Path,
        [switch]$Verbose
    )

    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    # Read the pcapng file as bytes
    $fileBytes = [System.IO.File]::ReadAllBytes($Path)
    
    Write-Host "Loaded pcapng file: $(($fileBytes.Length).ToString('F2')) Bytes"
    Write-Host "Searching for LLDP packets (Ethertype 0x88CC)..."

    $results = @()
    
    # Search for LLDP Ethertype marker (0x88CC) in the file
    # LLDP frames have Ethernet header: [6 bytes dest MAC][6 bytes src MAC][2 bytes Ethertype=0x88CC][LLDP payload]
    for ($i = 0; $i -lt $fileBytes.Length - 13; $i++) {
        # Check for LLDP Ethertype (0x88CC)
        if ($fileBytes[$i] -eq 0x88 -and $fileBytes[$i+1] -eq 0xCC) {
            Write-Host "`nFound LLDP Ethertype at offset 0x$($i.ToString('X4'))"
            
            # LLDP payload starts right after the Ethertype
            $lldpStart = $i + 2
            
            # Try to extract LLDP data (up to 1500 bytes or until we find end-of-PDU)
            $lldpLength = 0
            for ($j = $lldpStart; $j -lt [Math]::Min($lldpStart + 1500, $fileBytes.Length - 1); $j += 2) {
                $tlvType = ($fileBytes[$j] -shr 1) -band 0x7F
                $tlvLength = (($fileBytes[$j] -band 0x01) -shl 8) -bor $fileBytes[$j+1]
                $lldpLength += 2 + $tlvLength
                
                if ($tlvType -eq 0) { break } # End of PDU
            }
            
            if ($lldpLength -gt 2) {
                $lldpPayload = $fileBytes[$lldpStart..($lldpStart + $lldpLength - 1)]
                
                Write-Host "LLDP Payload size: $lldpLength bytes"
                Write-Host "Hex: $([System.BitConverter]::ToString($lldpPayload[0..([Math]::Min(31, $lldpPayload.Length-1))]))"
                
                $decoded = Decode-LLDP -Bytes $lldpPayload -Verbose:$Verbose
                $results += @{
                    Offset = $i
                    Size   = $lldpLength
                    Data   = $decoded
                }
            }
        }
    }

    return $results
}

# Interactive menu if no parameters are specified
if ($MyInvocation.InvocationName -eq '.') {
    # Script is dot-sourced, skip menu
    return
}

if ($args.Count -eq 0) {
    Write-Host "`n==== LLDP Debugger Interactive Menu ====" -ForegroundColor Cyan
    Write-Host "1. Find eligible interfaces for LLDP capture."
    Write-Host "2. Perform LLDP capture ALL eligible interfaces."
    Write-Host "3. Show LLDP ports from capture(s)."
    Write-Host "Q. Quit"
    $choice = Read-Host "`nSelect an option (1/2/3/Q)"

    # Helper: get eligible interfaces with pktmon index
    function Get-EligibleLLDPInterfaces {
        $adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Intel*" -and $_.Status -eq 'Up' }
        $pktmonRaw = pktmon comp list | findstr "Intel"
        $pktmon = @()
        foreach ($line in $pktmonRaw) {
            if ($line -match "^\s*(\d+) ([0-9A-Fa-f\-]+) (.+)$") {
                $pktmon += [PSCustomObject]@{
                    PktmonIndex = $matches[1]
                    MacAddress = $matches[2].ToUpper()
                    Description = $matches[3]
                }
            }
        }
        function Normalize-Mac($mac) { ($mac -replace '[^0-9A-Fa-f]', '').ToUpper() }
        $adapters | ForEach-Object {
            $adapterMac = Normalize-Mac $_.MacAddress
            $adapterDesc = $_.InterfaceDescription.Trim()
            $pkt = $pktmon | Where-Object {
                (Normalize-Mac($_.MacAddress) -eq $adapterMac) -and ($_.Description.Trim() -eq $adapterDesc)
            } | Select-Object -First 1
            [PSCustomObject]@{
                Name = $_.Name
                InterfaceDescription = $_.InterfaceDescription
                IfIndex = $_.ifIndex
                Status = $_.Status
                MacAddress = $_.MacAddress
                LinkSpeed = $_.LinkSpeed
                PktmonIndex = if ($pkt) { $pkt.PktmonIndex } else { '' }
                PktmonDescription = if ($pkt) { $pkt.Description } else { '' }
            }
        }
    }

    if ($choice -eq '1') {
        Write-Host "Gathering Intel network adapters (Status: Up)..." -ForegroundColor Yellow
        Get-EligibleLLDPInterfaces | Format-Table -AutoSize
        Write-Host "Done."
        exit
    } elseif ($choice -eq '2') {
        $interfaces = Get-EligibleLLDPInterfaces | Where-Object { $_.PktmonIndex -ne '' }
        foreach ($iface in $interfaces) {
            $NAME = $iface.Name
            # Use the first column (Name) and sanitize for filenames
            $BaseName = ($NAME -replace '\s+', '_')
            $PktmonIndex = $iface.PktmonIndex
            $etlFile = "$BaseName-lldp-cap.etl"
            $pcapFile = "$BaseName-lldp-cap.pcapng"
            Write-Host "Starting LLDP capture for $BaseName (PktmonIndex: $PktmonIndex)..." -ForegroundColor Yellow
            Write-Host "Output: $etlFile || pktmon start --capture --pkt-size 0 --file-name '$etlFile' --comp $PktmonIndex"
            pktmon filter remove
            pktmon filter add "LLDP" -d LLDP
            pktmon start --capture --pkt-size 0 --file-name "$etlFile" --comp $PktmonIndex
            for ($i=0; $i -le 35; $i++) {
                $percent = [int](($i/35)*100)
                Write-Progress -Activity "Capturing LLDP on $BaseName" -Status "$percent% complete" -PercentComplete $percent
                Start-Sleep -Seconds 1
            }
            Write-Progress -Activity "Capturing LLDP on $BaseName" -Status "Complete" -PercentComplete 100 -Completed
            pktmon stop
            Write-Host "Converting $etlFile to $pcapFile..." -ForegroundColor Yellow
            pktmon etl2pcap ".\$etlFile" -o ".\$pcapFile"
            Write-Host "Next..."
            Start-Sleep -Seconds 1
        }

        Write-Host "All captures complete."
        exit
    } elseif ($choice -eq '3') {
        $interfaces = Get-EligibleLLDPInterfaces | Where-Object { $_.PktmonIndex -ne '' }
        foreach ($iface in $interfaces) {
            $NAME = $iface.Name
            $BaseName = ($NAME -replace '\s+', '_')
            $pcapFile = "$BaseName-lldp-cap.pcapng"
            $pcapFilePath = Join-Path (Get-Location) "$BaseName-lldp-cap.pcapng"
            if (Test-Path $pcapFilePath) {
                Write-Host "Showing LLDP ports from $pcapFilePath for $BaseName :" -ForegroundColor Yellow
                $packets = Import-PcapngFile $pcapFilePath
                $packets | ForEach-Object { $_.Data | Format-Table -AutoSize }
            } else {
                Write-Host "No capture file found for $BaseName ($pcapFilePath)" -ForegroundColor Red
            }
        }
        Write-Host "Done."
        exit
    } elseif ($choice -eq 'Q' -or $choice -eq 'q') {
        Write-Host "Exiting."
        exit
    }
}
