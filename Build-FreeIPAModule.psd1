#
# Manifest for Build-IPAModule.psm1 module
#
# Generated by: Lucas Cueff
#
# Generated on : 02/2020
#

@{

# Module de script ou fichier de module binaire associe e ce manifeste
RootModule = 'Build-FreeIPAModule.psm1'

# Numero de version de ce module.
ModuleVersion = '0.8'

# editions PS prises en charge
# CompatiblePSEditions = @()

# ID utilise pour identifier de maniere unique ce module
GUID = 'd72a8ea1-c9a1-4528-a300-4de950379efc'

# Auteur de ce module
Author = 'LCU'

# Societe ou fournisseur de ce module
CompanyName = 'lucas-cueff.com'

# Declaration de copyright pour ce module
Copyright = '(c) 2018-2020 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'

# Description de la fonctionnalite fournie par ce module
Description = 'PowerShell Module used to build your own Manage-FreeIPA module based on your own server configuration. All functions and related binding code are automatically built based on your schema and env - https://github.com/freeipa/freeipa'

# Version minimale du moteur Windows PowerShell requise par ce module
PowerShellVersion = '4.0'

# Nom de l'hote Windows PowerShell requis par ce module
# PowerShellHostName = ''

# Version minimale de l'hete Windows PowerShell requise par ce module
# PowerShellHostVersion = ''

# Version minimale du Microsoft .NET Framework requise par ce module. Cette configuration requise est valide uniquement pour PowerShell Desktop Edition.
# DotNetFrameworkVersion = ''

# Version minimale de leenvironnement CLR (Common Language Runtime) requise par ce module. Cette configuration requise est valide uniquement pour PowerShell Desktop Edition.
# CLRVersion = ''

# Architecture de processeur (None, X86, Amd64) requise par ce module
# ProcessorArchitecture = ''

# Modules qui doivent etre importes dans l environnement global prealablement a l importation de ce module
# RequiredModules = @()

# Assemblys qui doivent etre charges prealablement a l importation de ce module
# RequiredAssemblies = @()

# Fichiers de script (.ps1) executes dans l environnement de l appelant prealablement a leimportation de ce module
# ScriptsToProcess = @()

# Fichiers de types (.ps1xml) a charger lors de l importation de ce module
# TypesToProcess = @()

# Fichiers de format (.ps1xml) a charger lors de l importation de ce module
# FormatsToProcess = @()

# Modules a importer en tant que modules imbriques du module specifie dans RootModule/ModuleToProcess
# NestedModules = @()

# Fonctions a exporter a partir de ce module. Pour de meilleures performances, neutilisez pas de caracteres generiques et ne supprimez pas leentree. Utilisez un tableau vide si vous neavez aucune fonction a exporter.
FunctionsToExport = 'Invoke-FreeIPAAPIJson_Metadata','Get-FreeIPAAPIAuthenticationCookie','Invoke-FreeIPAAPISessionLogout','Invoke-FreeIPAAPIEnv','Export-IPASchema','Export-IPAEnv','Publish-IPAModule','Get-IPAPCmdletName',
                    'Get-IPACmdletBinding','Get-IPACmdletBindingValue','Get-IPABindingCondition','Set-FreeIPAAPICredentials','Import-FreeIPAAPICrendentials','Set-FreeIPAAPIServerConfig','Get-ScriptDirectory','Set-FreeIPAProxy'


# Applets de commande a exporter a partir de ce module. Pour de meilleures performances, neutilisez pas de caracteres generiques et ne supprimez pas l entree. Utilisez un tableau vide si vous neavez aucune applet de commande e exporter.
CmdletsToExport = @()

# Variables a exporter a partir de ce module
# VariablesToExport = @()

# Alias a exporter a partir de ce module. Pour de meilleures performances, neutilisez pas de caracteres generiques et ne supprimez pas leentree. Utilisez un tableau vide si vous n avez aucun alias a exporter.
AliasesToExport = 'Get-IPAJsonMetadata','Connect-IPA','Disconnect-IPA','Get-IPAEnvironment','Set-IPAServerConfig','Import-IPACrendentials','Set-IPACredentials','Set-IPAProxy'

# Ressources DSC a exporter depuis ce module
# DscResourcesToExport = @()

# Liste de tous les modules empaquetes avec ce module
# ModuleList = @()

# Liste de tous les fichiers empaquetes avec ce module
FileList = 'Build-FreeIPAModule.psm1','IPAschema.xml', 'IPAenv.xml', 'Manage-FreeIPA_Mainfest_Template.file', 'Manage-FreeIPA_Module_Template.file'

# Donnees privees a transmettre au module specifie dans RootModule/ModuleToProcess. Cela peut egalement inclure une table de hachage PSData avec des metadonnees de modules supplementaires utilisees par PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('API','FreeIPA','IPA','Kerberos','Ldap','Identity-Management','identity')

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/MS-LUF/Build-FreeIPAModule'

        # A URL to an icon representing this module.
        IconUri = 'https://www.freeipa.org/images/freeipa/freeipa-logo-small.png'

        # ReleaseNotes of this module
        ReleaseNotes = 'Second public release of IPA Powershell Module Builder - Add multi config file as requested by baldator + Fix securestring issue reported by nadinezan + add proxy management to connect to IPA'
        # External dependent modules of this module
        # ExternalModuleDependencies = ''

    } # End of PSData hashtable
    
 } # End of PrivateData hashtable

# URI HelpInfo de ce module
# HelpInfoURI = ''

# Le prefixe par defaut des commandes a ete exporte a partir de ce module. Remplacez le prefixe par defaut a l aide de Import-Module -Prefix.
# DefaultCommandPrefix = ''

}