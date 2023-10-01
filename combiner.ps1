# In the combining script combine.ps1
$outputFileName = "system_tweaker.ps1"

# Folder where the .ps1 files are located (relative to the combining script)
$folderPath = Join-Path -Path $PSScriptRoot -ChildPath "scripts"

# List of individual file names
$functionFiles = @(
    "parameters.ps1",
    "global_vars.ps1",
    "restart_and_resume.ps1",
    "utils.ps1",
    "auto_update.ps1",
    "set_hostname.ps1",
    "set_ip.ps1",
    "main.ps1"
)

# Filter the list to include only files that exist in the "scripts" folder
$functionFiles = $functionFiles | Where-Object { Test-Path (Join-Path -Path $folderPath -ChildPath $_) }

# Create the combined file
$outputContent = @()
foreach ($file in $functionFiles) {
    # Add a comment at the beginning of the file
    $outputContent += "# START_FILE - $file - START_FILE`n"
    
    # Read the content of the file and add it
    $functionContent = Get-Content (Join-Path -Path $folderPath -ChildPath $file)
    $outputContent += $functionContent

    # Add a comment at the end of the file
    $outputContent += "`n# END_FILE - $file - END_FILE`n"
}

# Save the combined content to a file
$outputContent | Set-Content $outputFileName

