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

    Write-Verbose "Performing pre login activity for '$($user))'"
    # initial web request to get the login web form
    $preLogin = Invoke-WebRequest -Uri $Url -ErrorAction SilentlyContinue
    if ($preLogin.StatusCode -ne 200) { Write-Error "HTTP request for pre login failed with status $($preLogin.StatusCode) for user: $($user)" -ErrorAction Stop }

    # set web form values
    $form = $preLogin.Forms[0]
    $form.Fields["UserName"] = $user
    $form.Fields["Password"] = $password
    $form.Fields["AuthMethod"] = "FormsAuthentication"

    return $form.Fields
}