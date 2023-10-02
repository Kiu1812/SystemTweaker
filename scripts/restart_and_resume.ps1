# START - RESTART AND RESUME SCRIPT FUNCTIONS - START
function Test-Key([string] $path, [string] $key) {
    return ((Test-Path $path) -and ($null -ne (Get-Key $path $key)))   
}
function Remove-Key([string] $path, [string] $key) {
    Remove-ItemProperty -path $path -name $key
}
function Set-Key([string] $path, [string] $key, [string] $value) {
    Set-ItemProperty -path $path -name $key -value $value
}
function Get-Key([string] $path, [string] $key) {
    return (Get-ItemProperty $path).$key
}
function Restart-And-Run([string] $key, [string] $run) {
    Set-Key $global:RegRunKey $key $run
    Restart-Computer
    exit
}
function Clear-Any-Restart([string] $key = $global:restartKey) {
    if (Test-Key $global:RegRunKey $key) {
        Remove-Key $global:RegRunKey $key
    }
}
function Restart-And-Resume([string] $parameters) {
    Restart-And-Run $global:restartKey "$global:powershell -Command `"$global:scriptFullPath -Restarted $parameters`""
}
# END - RESTART AND RESUME SCRIPT FUNCTIONS - END