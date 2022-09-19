<#
.SYNOPSIS
    Gets the form fields to login to AD FS server for the login URL and credentials.
.DESCRIPTION
.EXAMPLE
    PS C:\>Get-LoginFormFields -Url $url -Credential $credential
    Gets the form fields for the variables.
#>
function Get-LoginFormFields {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string, string]])]
    param (
        # Login URL
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string] $Url,
        # User credential
        [Parameter(Mandatory = $true, Position = 1)]
        [pscredential] $Credential
    )

    $user = $Credential.UserName
    $password = ConvertFrom-SecureString $Credential.Password

    $fields = New-Object -TypeName "System.Collections.Generic.Dictionary[string,string]"
    $fields.Add("UserName",$user)
    $fields.Add("Password",$password)
    $fields.Add("AuthMethod","FormsAuthentication")

    return $fields
}