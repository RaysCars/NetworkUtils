#! /usr/bin/pwsh
[cmdletbinding()]
param (
   [ipaddress]$Subnet ,
   #[int]$CIDR = 24,
   [int]$Timeout = 300,
   [int]$Throttle = 256,
   [int]$PingCount = 1,
   [switch]$ResolveDns
)

## run online in Core
if($psversiontable.PsEdition -ne "Core"){
   write-host ""("#"*20) "`n  pwsh Core required `n" ("#"*20)
   exit
}


$varname =$Myinvocation.MyCommand.Name.Split(".")[0]

#$subnetMask = [ipaddress]([math]::pow(2, 32) -1 -bxor [math]::pow(2, (32 - $cidr))-1) | % { $_.IpAddressToSTring }

$arraylist = [System.Collections.ArrayList]::new()

Function GetSubnet {
   $subnets = [hashtable]::new()
   $tbl = @()
   $i=0
   if ($isLinux){
      
      $a = ip a
      # get adapter positions
      $adapters = $a | % { $i++ ; if($_ -match "^[0-9]"){ $i -1 }  }
      
      $i=0
      #loop through adapters
      $tbl = foreach ($adapter in $adapters){           
            #loop through lines after adpater looking for "inet "
            $notfound = $true
            $adapter .. ($adapter +3) | % {
               if ( $a[$_] -match "inet " -and $notfound){
                     $ip = $a[ $_ ].trim().split(" ")[1]
                     $ip = $ip.split("/")[0]           
                     $cidr = $ip.split("/")[1]
                     $i++
                     $notfound = $false
         
                     $row = [pscustomobject]@{
                        "#" = $i
                        IP = $ip ;
                        NIC = $a[ $adapter  ].split(":")[0,1] -join ":"
                     }
                     
                     $subnets.add($i, $row.ip )
                     $row       
         
                  }
         }#foreach -object
         
         
         
      }#tbl

   }else{
         Get-NetIPAddress -AddressFamily:IPv4 | ? { $_.InterfaceAlias -notmatch "loopback" } | % { 
            $i++
            $row = "" | select "#", Ip, NIC
            $row."#" = $i
            $row.ip = $_.IPAddress
            $row.NIC = $_.InterfaceAlias
            $tbl += $row
            $subnets.add($i, $row.ip )
         }
   }
      
   $tbl | format-table -auto | out-string | write-host
   
   Write-Host -foreground yellow "Select # of existing IP subnet or type a different subnet"

   do { $ans = Read-host } until ($ans -in (1.. $i) -OR ( $ans.Split(".").count -ge 3) )
   
   if ( $ans.Split(".").count -ge 3){
      $subnet = ([ipaddress]$ans).IpAddressToSTring
   }else{
      $subnet = $subnets[[int]$ans]
   }   
   
   return $subnet
}#Function GetSubnet




if (! $Subnet){
   $subnet = GetSubnet   
}



$SubnetToScan = $subnet.IPAddressToString 

$subnetPrefix = $SubnetToScan.split(".")[0..2] -join "."

if( $subnetPrefix.split(".").count -lt 3){
   write-host -foreground yellow Invalid "-Subnet $SubnetToScan"
   exit
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()

2..254 | Foreach-Object -ThrottleLimit $Throttle -Parallel {

      $ip = "$using:subnetPrefix.$_";  
      
      #WRITE-PROGRESS $ip "PINGing $ip"

      try { 
         $ping = [System.Net.NetworkInformation.Ping]::new().Send("$ip",$using:Timeout)
      }catch { $null|out-null }  

      if ($ping.Status -ne "Success" -or $ping -eq $null ){ continue }
      
      WRITE-PROGRESS $ip " Found $ip "
      
      $row = [pscustomobject]@{ "IP$(" "*13)" =  $ip ; "MS   " = $ping.RoundTripTime }

      if ($using:ResolveDns ) {  
         $row | Add-Member -Name FQDN -Value $null -Type:NoteProperty 
         try{ 
                  $row.FQDN = Test-Connection -Ping $ping.Address -Count 1 -Resolve | % { $_.Destination }
         }catch{        }
      }#if

      $row 
} |%  { $_; [void]$arraylist.Add($_)  }


#reformat the list to remove spaces from properties
Set-variable -Name $Varname -Scope Global -value ( $arraylist |
         Foreach-Object { 
               [PsCustomObject]@{
                  IP   = $_."IP$(" "*13)"
                  MS   = "MS   "
                  FQDN = $_.FQDN
               }
   }   | Sort-Object  { ([ipaddress]$_.ip).Address } 
)


write-host -foreground yellow "$((Get-Variable $varname).value.count) Results. `nStopwatch: " $sw.elapsed "Output results: `$$varname "

