# Get API key from https://ipgeolocation.io/
$API_KEY      = "REPLACE_WITH_YOUR_API_KEY"
$LOGFILE_PATH = "C:\ProgramData\failed_rdp.log"
$XMLFILE_PATH = "C:\ProgramData\failed_rdp_state.xml"

# SAFETY CHECK: Don't run if the user forgot to put their API key
if ($API_KEY -eq "REPLACE_WITH_YOUR_API_KEY" -or [string]::IsNullOrWhiteSpace($API_KEY)) {
    Write-Host "[ERROR] Please replace 'REPLACE_WITH_YOUR_API_KEY' with your actual ipgeolocation.io API key!" -ForegroundColor Red
    exit
}

# This script will run infinitely to keep extracting failed login attempts
while ($true) {
    
    # Setup state file to remember where we left off (look back 30 days)
    $state = @{ lastEventTime = (Get-Date).AddDays(-30) }
    if (Test-Path $XMLFILE_PATH) {
        $state = Import-Clixml $XMLFILE_PATH
    }
    
    # Get failed login events (Event ID 4625)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$state.lastEventTime} -ErrorAction SilentlyContinue
    
    if ($events) {
        $events | Sort-Object TimeCreated | ForEach-Object {
            $event = $_
            $state.lastEventTime = $event.TimeCreated
            
            # Extract IP Address from the event XML
            $xml = [xml]$event.ToXml()
            $ipAddress = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty '#text'
            
            # FILTER: Exclude empty IPs and localhost
            if ($ipAddress -and $ipAddress -ne "-" -and $ipAddress -ne "127.0.0.1") {
                
                # Check if IP is already in our log to save API calls (-SimpleMatch prevents regex dot bugs)
                $ipExists = $false
                if (Test-Path $LOGFILE_PATH) {
                    $ipExists = Select-String -Path $LOGFILE_PATH -Pattern $ipAddress -SimpleMatch -Quiet
                }
                
                if (-not $ipExists) {
                    # Call API to get Geolocation
                    try {
                        $url = "https://api.ipgeolocation.io/ipgeo?apiKey=$API_KEY&ip=$ipAddress"
                        $response = Invoke-RestMethod -Uri $url -Method Get
                        
                        $latitude = $response.latitude
                        $longitude = $response.longitude
                        $country = $response.country_name
                        $state_prov = $response.state_prov
                        $username = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty '#text'
                        $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        
                        # Format the output
                        $logOutput = "latitude:$latitude,longitude:$longitude,destinationhost:Honeypot-VM,username:$username,sourcehost:$ipAddress,state:$state_prov,country:$country,label:$country - $ipAddress,timestamp:$timestamp"
                        
                        # Print to screen AND write to log file with UTF8 encoding for international city names
                        Write-Host "FOUND ATTACKER -> $logOutput" -ForegroundColor Magenta
                        Add-Content -Path $LOGFILE_PATH -Value $logOutput -Encoding utf8
                        
                    } catch {
                        Write-Host "Failed to get geo data for IP: $ipAddress" -ForegroundColor Red
                    }
                }
            }
        }
        # Save state so we don't re-process old logs on restart
        $state | Export-Clixml $XMLFILE_PATH
    }
    
    # Wait 2 seconds before checking again
    Start-Sleep -Seconds 2
}