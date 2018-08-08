# Verify Running as Admin

function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function Set-Administrator ($CommandPath,$WorkingDir){

        Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
        Write-Host "File to run is $CommandPath and path to pass is $WorkingDir" 
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$CommandPath`"" -Verb RunAs -WorkingDirectory $WorkingDir

         
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output
Function Set-ScreenOffset {

1..10 |ForEach-Object { Write-Host ""}
}
#region Functions

function Write-InfoMessage($message){
        Write-Host $message
    }

function Write-InfoHighlightedMessage($message){
    Write-Host $message -ForegroundColor Cyan
}

function Write-SuccessMessage($message){
    Write-Host $message -ForegroundColor Green
}

function Write-ErrorMessage($message){
    Write-Host $message -ForegroundColor Red
}

function Write-ErrorMessageAndExit($message){
    Write-Host $message -ForegroundColor Red
    Write-Host "Press enter to continue ..."
    Stop-Transcript
    $exit=Read-Host
    Exit
}

function  Get-WindowsBuildNumber { 
    $os = Get-WmiObject -Class Win32_OperatingSystem 
    return [int]($os.BuildNumber) 
} 

Export-ModuleMember -Function *
#endregion