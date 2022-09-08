<#
.SYNOPSIS
    Initiates a logon request to and AD FS server to generate log activity.
.DESCRIPTION
    This command will acquire OAuth tokens for both public and confidential clients. Public clients authentication can be interactive, integrated Windows auth, or silent (aka refresh token authentication).
.EXAMPLE
    PS C:\>Get-AdfsActivityToken urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com
    Sign in to an application on an AD FS server using logged user credentials.
.EXAMPLE
    PS C:\>$credential = Get-Credential
    PS C:\>Get-AdfsActivityToken -Application urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com - $credential
    Sign in  to an application on an AD FS server using credentials provided by the user.
.EXAMPLE
    PS C:\>$password = ConvertTo-SecureString "P@ssW0rD!" -AsPlainText -Force
    PS C:\>$credential = New-Object PSCredential ('user2@contoso.com', $password)
    PS C:\>Start-AdfsActivity -Application urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com - $credential
    Sign in  to an application on an AD FS server using credentials passed via script.
.EXAMPLE
    PS C:\>$SamlIdentifiers =  Get-AdfsRelyingPartyTrust | where { $_.WSFedEndpoint -eq $null } | foreach { $_.Identifier.Item(0) }
    PS C:\>$SamlIdentifiers | foreach { Get-AdfsActivityToken $_ -Protocol SAML -AdfsHost sso.marcusca.net }
    Get all SAML relying party trusts from the AD FS server and sign in using the logged user credentials.
.EXAMPLE
    PS C:\>$WsFedIdentifiers = Get-AdfsRelyingPartyTrust | where { $_.WSFedEndpoint -ne $null -and $_.Identifier -notcontains "urn:federation:MicrosoftOnline" } | foreach { $_.Identifier.Item(0) }
    PS C:\>$WsFedIdentifiers | foreach { Get-AdfsActivityToken $_ -AdfsHost sso.marcusca.net }
    Get all Ws-Fed relying party trusts from the AD FS server excluding Azure AD and sign in using the logged user credentials.
#>
function Get-AdfsActivityToken 
{
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory=$true,
      Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage = 'Enter the application identifier')]
    [string]$Identifier,
    [Parameter(Mandatory=$true,
      HelpMessage = 'Enter host name for the AD FS server')]
    [string]$AdfsHost,
    [Parameter(Mandatory=$false,
      HelpMessage = 'Select the protocol for the application, SAML or WsFed (valid default is WsFed)')]
    [ValidateSet("SAML", "WsFed")]
    [string]$Protocol = "WsFed",
    [Parameter(Mandatory=$false,
      HelpMessage = 'Provide the credential for the user to be signed in.')]
    [pscredential]$Credential
  )

  if ($Protocol -eq "SAML") {
    $samRequest = New-AdfsActivitySamlRequestB64 $Identifier
    $uri = "https://$($AdfsHost)/adfs/ls?SAMLRequest=$([uri]::EscapeDataString($samRequest))"
  }
  else {
    # Defaults to Ws-Fed request
    $uri = "https://$($AdfsHost)/adfs/ls?client-request-id=$(New-Guid)&wa=wsignin1.0&wtrealm=$($Identifier)"
  }

  if ($null -ne $Credential) {
    $user = $Credential.UserName
    $form = Get-LoginFormFields -Url $uri -Credential $Credential
    $login = Invoke-WebRequest -Uri $uri -Method POST -Body $form -UseBasicParsing -ErrorAction SilentlyContinue
  }
  else {
    $userAgent = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)'
    $user = "$($env:USERDOMAIN)\$($env:UserName)"
    $login = Invoke-WebRequest -Uri $uri -UserAgent $userAgent -UseDefaultCredentials -UseBasicParsing -ErrorAction SilentlyContinue
  }

  if ($login.StatusCode -ne 200) { Write-Error "HTTP request failed with status $($login.StatusCode) for identifier ""$($identifier)"" and user: $($user)" }
  elseif ($login.InputFields.Count -le 0) { Write-Warning "Login failed for user: $($user)"}
  elseif ($login.InputFields[0].outerHTML.Contains("wsignin1.0")) {
    Write-Host "Login sucessful for identifier ""$($Identifier)"" and user: $($user) (Ws-Fed)"
    return $login.Content
  }
  elseif ($login.InputFields[0].outerHTML.Contains("SAMLResponse")) {
    Write-Host "Login sucessful for identifier ""$($Identifier)"" and user: $($user) (SAML)"
    return $login.Content
  }
  else { Write-Warning "Login failed for identifier ""$($Identifier)"" and user: $($user)" }

  return
}
