<#
.SYNOPSIS
    Convert Base64 string to UTF-8 plain text string.
.EXAMPLE
    PS C:\>ConvertFrom-Base64String "c2FtcGxlIGlucHV0"
    Convert "c2FtcGxlIGlucHV0" to UTF-8 plain text string.
#>
function ConvertFrom-Base64String {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Base64 string value
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string] $base64
    )

    $text = [System.Convert]::FromBase64String($base64)
    return [System.Text.Encoding]::UTF8.GetString($text)
}