# Build-FreeIPAModule
a few PowerShell cmdlets to build your own IPA/FreeIPA Powershell management Module - https://github.com/freeipa/freeipa

(c) 2018 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## Description
Build-FreeIPAModule.psm1 PowerShell module provides a set of PowerShell cmdlets to build your own FreeIPA/IPA management module to manage your FreeIPA/IPA infrastructure from Powershell (Core/Classic - Windows/Linux/Mac Os).
This module will use JSON_Metadata and env APIs from your IPA Server to dynamically generate all PowerShell functions code and bindings for your personal environment.

## Note
For more information on the FreeIPA API, please connect to the web interface on your IPA Server : https://yourIPA.domain.tld/ipa/ui/#/p/apibrowser/type=command
Don't forget to trust your IPA AC / ssl certificate locally before using the Powershell Module.
**Please unload your manage-FreeIPA module before loading the build module because some functions and alias are shared**
```
	C:\PS> Remove-Module Manage-FreeIPA
```

## Documentation
To do ;)

## Install Manage-ADShadowGroup from PowerShell Gallery repository
You can easily install it from powershell gallery repository https://www.powershellgallery.com/packages/Manage-FreeIPA/ using a simple powershell command and an internet access :-)
```
	Install-Module -Name Build-FreeIPAModule
```

## import module from PowerShell 
```
	C:\PS> import-module Build-FreeIPAModule.psm1
```

## Exported Functions and Alias
### Functions
- Export-IPAEnv
- Export-IPASchema
- Get-FreeIPAAPIAuthenticationCookie
- Get-IPABindingCondition
- Get-IPACmdletBinding
- Get-IPACmdletBindingValue
- Get-IPAPCmdletName
- Get-ScriptDirectory
- Import-FreeIPAAPICrendentials
- Invoke-FreeIPAAPIEnv
- Invoke-FreeIPAAPIJson_Metadata
- Invoke-FreeIPAAPISessionLogout
- Publish-IPAModule
- Set-FreeIPAAPICredentials
- Set-FreeIPAAPIServerConfig                        
### Alias
- Connect-IPA
- Disconnect-IPA
- Get-IPAEnvironment
- Get-IPAJsonMetadata
- Import-IPACrendentials
- Set-IPAServerConfig
- Set-IPACredentials                                     

## Use the module
### Set your config and be authenticated with your server
Set your encrypted credential in cache for future use and set it also in an external file if necessary (EncryptKeyInLocalFile and MasterPassword)
```
	C:\PS> Set-IPACredentials -AdminLogin (ConvertTo-SecureString -String "adminlogin" -AsPlainText -Force) -AdminPassword (ConvertTo-SecureString -String "adminpass" -AsPlainText -Force)
```
Set your FreeIPA server URL info
```
	C:\PS> Set-IPAServerConfig -URL https://yourIPA.domain.tld
```
Get your authentication cookie to be authenticated with your APIs
```
	C:\PS> Connect-IPA -UseCachedURLandCredentials
```
### Export your current environment and schema
Generate your PowerShell environement file from your current IPA environment (default file is IPAEnv.xml)
```
	C:\PS> Export-IPAEnv
```
Generate your Powershell schema file from your current IPA environment (default file is IPASchema.xml)
```
	C:\PS> Export-IPASchema
```
### Generate your custom module based on your current IPA configuration
Generate your custom IPA PowerShell management module based on your schema and environment
```
	C:\PS> Publish-IPAModule -IPASchemaRef "C:\Users\tst\Documents\GitHub\Build-FreeIPAModule\IPAschema.xml" -IPAEnvRef "C:\Users\tst\Documents\GitHub\Build-FreeIPAModule\IPAenv.xml" -BuilderName "You" -Version "1.0" -VersionComment "Your First Release"


	ManifestFileName : C:\Users\tst\Documents\GitHub\Build-FreeIPAModule\Manage-FreeIPA_Build_636781623970522876.psd1
	Version          : 1.0
	Alias            : {Add-IPAAci, Remove-IPAAci, Find-IPAAci, Set-IPAAci...}
	BuildingDate     : 18/11/2018 18:26:37
	ModuleFileName   : C:\Users\lcu\Documents\GitHub\Build-FreeIPAModule\Manage-FreeIPA_Build_636781623970522876.psm1
	Builder          : You
	Changelog        : Your First Release
	Functions        : {Invoke-FreeIPAAPIAci_Add, Invoke-FreeIPAAPIAci_Del, Invoke-FreeIPAAPIAci_Find, Invoke-FreeIPAAPIAci_Mod...}
```
Disconnect from the server
```
	C:\PS> Disconnect-IPA
```
### Example : Automate all the things :)
Check the sample script "Sample_Generate-FunctionsFromAPI.ps1" to have some idea ;)