<#
.SYNOPSIS
    Convert string to deflated array of bytes.
.DESCRIPTION
.EXAMPLE
    PS C:\>ConvertTo-DeflateArray 'My text to be reduced'
    Convert string to deflated array of bytes.
#>
function ConvertTo-DeflateArray  {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param (
        # Secure String Value
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string] $text
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)

    $output = New-Object System.IO.MemoryStream
    $zip = New-Object System.IO.Compression.DeflateStream($output, [System.IO.Compression.CompressionMode]::Compress)
    $zip.Write($bytes, 0, $bytes.Length)
    $zip.Close()
    $deflate = $output.ToArray()
    $output.Close()

    return $deflate
}