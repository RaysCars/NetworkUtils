<#
   .AUTHOR Mark McInturff - mark.mcinturff@kyndryl.com or mmcint@gmail.com
   
   .VERSION 2022.12.20
   
   .PROJECTURI https://github.kyndryl.net/cmm-automation-guild-americas/Scan-Ports
#>

[CmdletBinding()] 
param (
   #[Parameter(ValueFromPipeline = $true)]
   $Computer, 
   [pscustomobject]$PortRange,
   [Switch]$AllPorts, 
   [Switch]$CommonPorts , 
   [Switch]$ScanUnresponsive,
   [int]$Timeout = 1000,
   [switch]$udp,
   [switch]$Silent,
   [switch]$MultiThread,
   [int]$THROTTLE = 24,
   [Switch]$Help
)

begin {

   if (! $IsWindows){
      #not powershell core
      write-host -foreground white -background red "Requires Powershell Core (pwsh) "
      exit
   }
   
   if(! $Computer){
      write-host -foreground white -background red  "Required: -Computer"
      exit
   }
   

   Function WriteProgress {
      if ($isSilent -or $silent) { return $Null }
      Write-Progress @args
   }
   
   #remove previous jobs in case ctrl-c was pressed
   Get-job | ? { $_.id -in $allJobs.id } | % { $_ | Stop-Job ; $_ | Remove-Job } 
   $Global:allJobs = [System.Collections.ArrayList]::new()
   $jobs = [System.Collections.ArrayList]::new()
   [void]$jobs.Add([PSCustomObject])


   ## explain no UDP
   if ($udp) {
      write-host -ForegroundColor Yellow " UDP OUT OF SCOPE because it is connectionless, therefore data must `n be sent then a response received. `n Because services for anygiven port is unkonwn, `n determing the existence of `n a listening UDP port is"
      exit
   }
   
   ## show help
   if ($Help) {
      get-help $MyInvocation.mycommand -Full | more
      exit
   }
   
   $computers = [System.Collections.ArrayList]::new()
   
   if ( $computer -match "-") { $delim = "-" }
   elseIf ( $computer -match "\.\.") { $delim = ".." }
   
  
   if ($delim) {
      $computer.split($delim)[0].split(".")[3] .. $computer.split($delim)[1] | Foreach-object {
         $ip = $computer.split($delim)[0].split(".")[0..2] -join "." 
         [void]$computers.Add( [ipaddress]($ip + ".$_") ) 
      }
   }#end if             
   
   
   
   #define selected portrange
   if ( ("$PortRange" -match "\.\.") ) {
      $PortRange = $portrange.split("..")[0].trim() .. $portrange.split("..")[1].trim()
   } elseif ( ( "$PortRange" -match "-" ) ) {
      $PortRange = [int]$portrange.split("-")[0] .. [int]$portrange.split("-")[1]
   }
   
}



process { 
   if (! $computers) {
      [void]$computers.Add( $computer )
   }   
   
}

end {

   $Global:stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

   
   if ( $portsList.count -gt 0 ) {
      #variable pre-exists from last run
   } elseIF (!!( get-item ~/latestports.csv  -ErrorAction:SilentlyContinue)) {
      WriteProgress "Caching port descriptions" "from file ~/latestports.csv"
      ## set portlist as jobs to reuse for multiple runs
      $Global:portsList = [hashtable]::new()  
      #GET-CONTENT ~/latestports.csv | ConvertFrom-Csv  | Where-Object number -NotMatch "[a-z]" | Group-Object  number, protocol   | ForEach-Object { $_.Group | Select-Object -f 1 }  | ForEach-Object { [void]$portsList.Add( ($_.number + $_.protocol) , $_.Description ) } 
      GET-CONTENT ~/latestports.csv | ConvertFrom-Csv  | Where-Object number -NotMatch "[a-z]" | Sort-Object -Unique number, protocol   | % { [void]$portsList.Add( ($_.number + $_.protocol) , $_.Description ) } 
   } else {
      $url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml"
      WriteProgress "Caching port descriptions" "$url"
      try { 
         [xml]$LatestPorts = (Invoke-WebRequest -Uri $url ).Content
      
      $Global:portsList = $LatestPorts.ChildNodes.record | Select-Object number, protocol, description | Where-Object { $_.number }
      ## output portlist to csv
      $Global:portsList | ConvertTo-Csv -NoTypeInformation > ~/latestports.csv 
      ##index to hashtable
      $Global:PortsList = $Global:PortsList | %  { @{ ($_.number + $_.protocol) = $_.Description } }
      }catch {
         #no connection to internet
         #$Global:portsList = [hashtable]::new()  
      }
   }
   
   Function RowDef { "" | Select-Object Dst, Port, Open, Desc }

   Function GetPort {
      param($dst, $PortRange, $Protocol, [Switch]$IsSilent)
      
      process {
         
         $PingSuccess = $True
         if(! $ScanUnresponsive){
            $PingSuccess = (Test-Connection $dst -Count 1 -Ping -IPv4 -ResolveDestination:$false -TimeoutSeconds 1 -Quiet)
         }   
         
         if($ScanUnresponsive){
            $unresponsive = [PsCustomObject]@{
            Dst  = "$($splatGetport['dst'])"
            Port = $Null
            Open = $null
            Desc = "NO CONNECTION" 
            }
         }
         
         if (!( $PingSuccess -or $ScanUnresponsive)) {
            WriteProgress "$dst" "unresponsive "
            CONTINUE
         }
         

         
         WriteProgress "$dst" "Total Ports: $($portrange.count)"
         $global:tasks = [System.Collections.ArrayList]::new()
         [void]$global:tasks.Add([pscustomobject])
         
         Foreach ($port in $PortRange) {
            $row = "" | select-object tcpClient, task, dst, port, timer
            WriteProgress "Queing ports ($proto):" "$port"
            $tcpClient = [System.Net.Sockets.TCPClient]::new() ;
            $tcpClient.client.ReceiveTimeout = 500 ;
            $tcpClient.client.SendTimeout = 500 ;
            try { $row.task = $tcpClient.ConnectAsync( $dst , $port ) }
            catch {
               $row = RowDef
               $row.dst = $dst
               $row.port = $port
               $row.Desc = "EPHEMERAL PORTS BUFFER SPACE FULL"
               WriteProgress "$dst : $port " "  $($row.Desc) "
               $tcpClient.close(); $tcpClient.Dispose()
               continue
            }
            $row.tcpClient = $tcpClient
            $row.dst = $dst
            $row.port = $port
            $row.timer = $null # [System.Diagnostics.Stopwatch]::StartNew()
            #tcpClient.NoDelay -eq $false means attempt complete
            #debug write-host "$dst :$port"
            [void]$tasks.Add( $row )
         }#foreach $Portrange
                  
         [void]$tasks.Remove($tasks[0]) #instantiation object
         $script:ROWS = [System.Collections.ArrayList]::new()
         $script:completed = [System.Collections.ArrayList]::new()
         
         do {
            $completed_tasks = $tasks | Where-Object { $_.task.IsCompleted -eq $True } 
            WriteProgress -Activity $dst -Status "Ports: $($tasks.port -join ",")"
            $completed_tasks | ForEach-Object {  
               [void]$tasks.Remove($_) ; 
               [void]$completed.Add($_) ;
            }
            
            foreach ($item in $completed_tasks) {
               $connected = $item | Where-Object { $_.task.Status -ne "faulted" }
               $connected | ForEach-Object {
                  $row = RowDef
                  $row.Dst = $connected.dst
                  $row.Port = $connected.port
                  $row.open = $connected.tcpClient.Connected
                  $Desc = $portsList[ [string]$row.port + "tcp" ]
                  $row.Desc = $Desc
                     
                  if ($row) {   
                     $row 
                     [void]$ROWS.Add($row) ; 
                     
                  }
               } ## end $tasks
                  
               $item | ForEach-Object { $_.tcpClient.Close() }
            } ##end foreach ($item in $completed_tasks) 
         }until( $tasks.count -eq 0 )
         
         #close tcp connections 
         $completed | ForEach-Object { 
            write-verbose "Closing Ports $($_.tcpClient.Client.RemoteEndPoint) "
            $_.tcpClient.close() 
         }
         
      }#process
   }#End Function GetPort
   
   $protocol = "tcp"

   $PortSelected = @()

   if ($PortRange) {
      $PortSelected += $PortRange
   }else{
      if (!($AllPorts -OR $CommonPorts)){
         $CommonPorts = $True
      }
   }

   

   IF ($AllPorts) {
      $PortSelected += 0..65535
   }

   IF ($CommonPorts) {
      $PortSelected += 0,1,5,7,9,11,13,17,18,19,20,21,22,23,25,35,37,38,39,41,42,43,49,53,57,67,68,69,70,79,80,81,82,88,102,110,119,123,135,137,138,139,143,161,162,389,443,445,464,500,515,548,554,563,593,636,993,995,1067,1068,1270,1433,1434,1645,1646,1701,1723,1755,1801,1812,1813,1900,2101,2103,2105,2107,2393,2394,2460,2535,2701,2702,2703,2704,2725,2869,3268,3269,3343,3389,3527,4011,4500,5000,5004,5005,5357,5722,6001,6002,6004,7070,7501,7631,7680,8080,8081,8384,9000,9001,9090,9617,42424,51515
   }

   IF ($RTSP) {
      $PortSelected += 80, 81, 554, 7070, 8080, 8081
   }
   
   $PortSelected = $PortSelected | sort-object -unique
   
   Foreach ($comp in $computers ) {
      $parms = ($script:psboundparameters.keys | ForEach-Object { "$($_) $($script:psboundparameters[$_] -join "," ) " } ) -join "-"
      WriteProgress -Activity $comp -Status " $parms "
      
      $arglist = @{ 
         splatGetPort = @{
            Dst       = $comp
            PortRange = $PortSelected 
            Protocol  = $protocol 
            IsSilent  = if ($computers.count -LT 10){ $false }else{ $True }
         }
         Functions    = (Get-ChildItem function:GetPort, function:writeprogress, Function:Rowdef) 
         portsList    = $portsList
      }
      
      $block = {
         $arglist = $args[0]
         $splatGetport = $arglist.splatGetPort
         $portsList = $arglist.portsList
         
         #initalize functions
         $arglist.Functions  | ForEach-Object { Invoke-Expression "$($_.CommandType) $($_.Name) { $($_.ScriptBlock) }" }

         GetPort  @splatGetport
         
         
      }#block

      if ($computers.count -LT 10 -AND (! $MultiThread) ) {
         $splatGetPort = $arglist.splatGetPort
         GetPort @splatGetPort
         
      } else {
         $job = Start-ThreadJob -Name $comp -ArgumentList $arglist -Throttle $THROTTLE -ScriptBlock  $block -verbose:$VerbosePreference 
         [void]$jobs.Add($job)
      }
      
   }#Foreach ($comp in $computers ) 

   $ROWS = [System.Collections.ArrayList]::new()
      
   $jobscount = $jobs.count
   
   $jobs[1.. $jobs.count] | % { [void]$Global:AllJobs.Add($_) }
   
   while ( $jobs.count -GT 1 ) { 
      $jobsCompleted = $jobs | Where-Object State -EQ "Completed"
      if($jobsCompleted){ $name = $jobsCompleted.name | select -L 1 }
      WriteProgress "$name | $($Stopwatch.Elapsed.toString('d\d\:h\h\:m\m\:s\s'))"  "Multithread $($jobscount - $jobs[1..1kb].count)/$jobscount IP scans" -PercentComplete (($jobscount -($jobs.count  )) / $jobscount * 100)
      foreach ($Global:jc in $jobsCompleted) {
         $row = $null
         $row = Receive-Job $jc
         Write-Output $row
         #$row | Where-Object { $_ } | ForEach-Object { $_ }
         $row | ForEach-Object { [void]$ROWS.Add($_) }
         remove-job $jc

         [void]$jobs.Remove($jc)
      }
      
   }

   
   
   
   $Stopwatch.Stop()
   $scansPerSec = $([int]($PortSelected.count / $Stopwatch.Elapsed.TotalSeconds))
   $LastOutput = "" | Select-Object PortsScanned, ScanPerSecond, Stopwatch, Rows, Parameters, PortRange
   $LastOutput.PortsScanned = ($PortSelected.count)
   $LastOutput.PortRange = $PortSelected
   $LastOutput.ROWS = $ROWS; 
   $LastOutput.Parameters = $PsBoundParameters; 
   $LastOutput.Stopwatch = $Stopwatch.Elapsed.toString('d\d\:h\h\:m\m\:s\s\:fff\m\s') 
   $LastOutput.ScanPerSecond = $scansPerSec ; ; 
   $ROWSName = ($MyInvocation.MyCommand.Name.split(".")[0])
   Set-Variable -Name $ROWSName -Scope Global -Value $LastOutput
   write-host -foreground yellow " IPs: $($computers.count) | Ports Scanned: $($PortSelected.count)  | ScansPerSecond: $scansPerSec | STOPWATCH: $($Stopwatch.Elapsed) 
   SEE `$$ROWSName for ROWS "

}#end

<#

.SYNOPSIS
    Fast port scanner to replace my compiled scanner that Windows Security deleted as a security risk.
    

.Description
   Performs asynchronous port scan of specified ports and IP addresses.

.PARAMETER Computer
    one or more computer names or IP addresses. Other notation can be used for blocks of IP addresses
    Examples:
    -Computer 192.168.0.2                # single IP port scan
    -Computer 192.168.0.2, 192.168.0.3   # multiple IP port scan
    -Computer 192.168.0.2-200            # block of IP port scan
    -Computer 192.168.0.2..200           # same as above

.PARAMETER PortRange
  Usage:
    80
    22,80
    80..900

.PARAMETER CommonPorts
    A collection of most common ports are scanned

.PARAMETER AllPorts
    All TCP ports. Warning, this can exhaust the tcp ports the SOURCE computer running this script. 
 
.PARAMETER Timeout
  Default timeout is 1000 milliseconds (1 second). Change as desired.

 .PARAMETER ScanUnresponsive
 By Default, unresponsive Computer (ping) is skipped. ScanUnresponsive forces scan of unresponsive Computer.
  
.Link 
   https://github.kyndryl.net/cmm-automation-guild-americas/Scan-Ports/upload
   
 .Example 
   Scan-Ports.ps1 -Computer 192.168.0.2 -PortRange 22
   #scans only port 22
   
 .Example 
   Scan-Ports.ps1 -Computer 192.168.0.2 -PortRange 22..999
   
 .Example 
   Scan-Ports.ps1 -Computer 192.168.0.2 -PortRange 3289,5480 -CommonPorts
   
   #scans ports 22 common ports in addition to 3289 and 5480

#>