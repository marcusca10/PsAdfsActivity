<#
.SYNOPSIS
    Create a SAML request encoded as Base64.
.EXAMPLE
    PS C:\>New-AdfsActivitySamlRequestB64 urn:federation:MicrosoftOnline
    Create a SAML request for the application urn:federation:MicrosoftOnline.
#>
function New-AdfsActivitySamlRequestB64 {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Application identifier
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [securestring] $Identifier
    )

    $id = "id$((New-Guid).ToString() -replace '-','')"
    $instant = (Get-Date).ToUniversalTime().ToString("o") #"2013-03-18T03:28:54.1839884Z"

    $samlRequest = "<samlp:AuthnRequest xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""$($id)"" Version=""2.0"" IssueInstant=""$($instant)"" xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""><Issuer xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">$($Identifier)</Issuer></samlp:AuthnRequest>"

    $bytes = ConvertTo-DeflateArray $samlRequest
    return [System.Convert]::ToBase64String($bytes)
}