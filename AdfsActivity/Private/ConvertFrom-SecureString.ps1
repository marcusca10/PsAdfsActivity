<#
.SYNOPSIS
    Convert/Decrypt SecureString to Plain Text String.
.EXAMPLE
    PS C:\>ConvertFrom-SecureString (ConvertTo-SecureString 'SuperSecretString' -AsPlainText -Force)
    Convert plain text to SecureString and then convert it back.
#>
function ConvertFrom-SecureString {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Secure String Value
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [securestring] $SecureString
    )

    return [Net.NetworkCredential]::new('', $SecureString).Password
}