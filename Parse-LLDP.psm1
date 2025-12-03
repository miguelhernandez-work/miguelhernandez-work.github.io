#version 1 - 2025-12-02: Describes how to capture and parse an LLDP frame using Windows native tool 'pktmon',
# ... 1) add the LLDP filter via: pktmon filter add "LLDP" -d LLDP
# ... 2) capture via: pktmon start --capture --pkt-size 0 --file-name "$intfName-lldp-cap.etl" --comp 17
# ... 3) convert the etl to pcapng: pktmon etl2pcap  .\'$intfName-lldp-cap.etl' -o .\$intfName-lldp-cap.pcapng
# ... 4) Decode the interesting LLDP bytes from the frame: Import-Module 'path\to\Parse-LLDP.psm1'
# ... 5) $packets = Import-PcapngFile "\path\to\$intfName-lldp-cap.pcapng"
# ... 6) $packets.Data
# }
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
    
    Write-Host "Loaded pcapng file: $(($fileBytes.Length / 1MB).ToString('F2')) MB"
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


# Export functions
Export-ModuleMember -Function Decode-LLDP, Import-PcapngFile
