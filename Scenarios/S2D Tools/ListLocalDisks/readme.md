Simple script to list all s2d cluster nodes and it's disks.

```PowerShell
$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 | Out-GridView -OutputMode Single -Title "Please select your S2D Cluster").Name

$nodes=Get-StorageSubSystem -CimSession $clusterName -FriendlyName Clus* | Get-StorageNode
$disks=@()
foreach ($node in $nodes) {
    $disks+=Invoke-Command -ComputerName $node.Name -ScriptBlock {
        $using:node | Get-PhysicalDisk -PhysicallyConnected
        }
     }

$disks | select PSComputerName,friendlyname,SerialNumber,healthstatus,OperationalStatus,CanPool,physicallocation,slotnumber | Out-GridView
#or all 
$disks | select * | ogv 
```