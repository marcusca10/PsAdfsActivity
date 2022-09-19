<#
.SYNOPSIS
    Initiates a logon request to and AD FS server to generate log activity.
.DESCRIPTION
    This command will acquire OAuth tokens for both public and confidential clients. Public clients authentication can be interactive, integrated Windows auth, or silent (aka refresh token authentication).
.EXAMPLE
    PS C:\>Get-AdfsActivityToken urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com
    Sign in to an application on an AD FS server using logged user credentials using the WindowsTransport endpoint.
.EXAMPLE
    PS C:\>$credential = Get-Credential
    PS C:\>Get-AdfsActivityToken urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com -Credential $credential
    Sign in  to an application on an AD FS server using credentials provided by the user using the UserNameMixed endpoint.
.EXAMPLE
    PS C:\>Get-AdfsActivityToken urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com -Protocol WsFed
    Sign in to an application on an AD FS server using logged user credentials using the Ws-Fed protocol.
.EXAMPLE
    PS C:\>$credential = Get-Credential
    PS C:\>Get-AdfsActivityToken urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com -Protocol WsFed
    Sign in  to an application on an AD FS server using credentials provided by the user using the Ws-Fed endpoint and forms based authentication.
.EXAMPLE
    PS C:\>$password = ConvertTo-SecureString "P@ssW0rD!" -AsPlainText -Force
    PS C:\>$credential = New-Object PSCredential ('user2@contoso.com', $password)
    PS C:\>Get-AdfsActivityToken urn:federation:MicrosoftOnline -AdfsHost adfs.contoso.com -Credential $credential
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
      HelpMessage = 'Select the protocol for the application: WsTrust, SAML or WsFed (valid default is WsTrust)')]
    [ValidateSet("SAML", "WsFed", "WsTrust")]
    [string]$Protocol = "WsTrust",
    [Parameter(Mandatory=$false,
      HelpMessage = 'Provide the credential for the user to be signed in.')]
    [pscredential]$Credential
  )

  if ($null -ne $Credential) 
  {
    Write-Warning "Using credentials sends password in clear text over the network!"
  }


  $login = $null
  $loginFail = ""

  if ($Protocol -eq "WsTrust") {
    if ($null -ne $Credential) {
      $user = $Credential.UserName
      $uri = "https://$($AdfsHost)/adfs/services/trust/2005/usernamemixed"

      $wstrustRequest = New-AdfsActivityWsTrustRequest $Identifier -AdfsHost $AdfsHost -Credential $Credential
      try{
        $login = Invoke-WebRequest $uri -Method Post -Body $wstrustRequest -ContentType "application/soap+xml" -UseBasicParsing #-ErrorAction SilentlyContinue
      }
      catch [System.Net.WebException]{
        $loginFail = $_
      }
    }
    else {
      $uri = "https://$($AdfsHost)/adfs/services/trust/2005/windowstransport"
      $user = "$($env:USERDOMAIN)\$($env:UserName)"

      $wstrustRequest = New-AdfsActivityWsTrustRequest $Identifier -AdfsHost $AdfsHost
      try{
        $login = Invoke-WebRequest $uri -Method Post -Body $wstrustRequest -ContentType "application/soap+xml" -UseDefaultCredentials -UseBasicParsing -ErrorAction SilentlyContinue
      }
      catch [System.Net.WebException]{
        $loginFail = $_
      }
    }
  }
  else {
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
      try{
        $login = Invoke-WebRequest -Uri $uri -Method POST -Body $form -UseBasicParsing -ErrorAction SilentlyContinue
      }
      catch [System.Net.WebException]{
        $loginFail = $_
      }
    }
    else {
      $userAgent = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)'
      $user = "$($env:USERDOMAIN)\$($env:UserName)"
      try{
        $login = Invoke-WebRequest -Uri $uri -UserAgent $userAgent -UseDefaultCredentials -UseBasicParsing -ErrorAction SilentlyContinue
      }
      catch [System.Net.WebException]{
        $loginFail = $_
      }
    }
  }



  if ($null -eq $login) { Write-Error "HTTP request failed for identifier ""$($identifier)"" and user: $($user). ERROR: $($loginFail)" }
  elseif ($login.StatusCode -ne 200) { Write-Error "HTTP request failed for identifier ""$($identifier)"" and user: $($user). ERROR: HTTP status $($login.StatusCode)" }
  elseif ($login.InputFields.Count -le 0) {
    if ($login.Headers["Content-Type"].Contains("application/soap+xml")) {
      Write-Host "Login sucessful for identifier ""$($Identifier)"" and user: $($user) (Ws-Trust)"
      return $login.Content
    }
    else { Write-Warning "Login failed for user: $($user)" }
  }
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
