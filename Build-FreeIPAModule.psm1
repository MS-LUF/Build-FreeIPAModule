#
# Created by: lucas.cueff[at]lucas-cueff.com
# Build by : Lucas Cueff
# v0.7 : First Release
# v0.8 : Add multi config file as requested by baldator + Fix securestring issue reported by nadinezan + add proxy management to connect to IPA
#
# Released on: 22/02/2020
#
#'(c) 2018-2020 lucas-cueff.com - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'

<#
	.SYNOPSIS 
	Powershell cmdlets to build FreeIPA Poweshell Module management

	.DESCRIPTION
    Build-iPAModule.psm1 module provides a commandline interface to build your own FreeIPA/IPA Management Powershell Module. Works for Powershell (Core/Classic(starting v4) - Windows/Linux/Mac Os).
    This module will use JSON_Metadata and env APIs from your IPA Server to dynamically generate all functions code and binding for your personal environment.
    For more information on the FreeIPA API, please connect to thw web interface on your IPA Server : https://yourIPA.tld/ipa/ui/#/p/apibrowser/type=command
    Note : Don't forget to trust your IPA AC / ssl certificate locally before using the Powershell Module.
	
	.EXAMPLE
    C:\PS> import-module Build-FreeIPAModule.psm1
#>
Function Get-ScriptDirectory {
    Split-Path -Parent $PSCommandPath
}
Function Export-IPASchema {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [string]$IPASchemaRef
    )
    If (!($IPASchemaRef)) {
        $IPASchemaRef = join-path (Get-ScriptDirectory) "IPAschema.xml"
    }
    export-clixml -path $IPASchemaRef -InputObject (Invoke-FreeIPAAPIJson_Metadata).commands
}
Function Export-IPAEnv {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [string]$IPAEnvRef
    )
    If (!($IPAEnvRef)) {
        $IPAEnvRef = join-path (Get-ScriptDirectory) "IPAenv.xml"
    }
    export-clixml -path $IPAEnvRef -InputObject (Invoke-FreeIPAAPIEnv)
}
Function Invoke-FreeIPAAPIEnv {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [parameter(Mandatory=$false)]
            [switch]$All,
        [parameter(Mandatory=$false)]
            [switch]$FullResultsOutput
    )
    process {
        $EnvParams = New-Object psobject -property @{
            version = $global:FreeIPAAPIServerConfig.ClientVersion
        }
        if ($All.IsPresent) {
            $EnvParams | Add-Member -NotePropertyName all -NotePropertyValue $true
        }
        $EnvObject = New-Object psobject -property @{
            id		= 0
            method	= "env/1"
            params  = @(@(),$EnvParams)
        }
        if (!($FullResultsOutput.IsPresent)) {
            (Invoke-FreeIPAAPI $EnvObject).result.result
        } else {
            Invoke-FreeIPAAPI $EnvObject
        }
    } 
}
Function Get-IPAPCmdletName {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Object]$inputSchemaObject
    )
    process {
        if (!($inputSchemaObject.name) -and !($inputSchemaObject.doc)) {
            throw "Input object not valid"
        }
        $IPAAPIName = $inputSchemaObject.name
        $IPAAPIDoc = $inputSchemaObject.doc
        switch (($IPAAPIName -split '_').count) {
            1 {
                New-Object psobject -property @{
                    PWshFunctionName = "Invoke-FreeIPAAPI" + (Get-Culture).TextInfo.ToTitleCase($IPAAPIName)
                    PWshAliasName	 = "Use-IPA" + (Get-Culture).TextInfo.ToTitleCase($IPAAPIName)
                    CmdletDoc        = $IPAAPIDoc
                }
            }
            2 {
                $TmpAPIName = ($IPAAPIName -split '_')[0]
                $TmpPWSVerb = ($IPAAPIName -split '_')[1]
                switch ($TmpPWSVerb) {
                    "mod" {$PWshAliasName = "Set-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "undel" {$PWshAliasName = "Restore-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "status" {$PWshAliasName = "Get-IPAStatus" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "reinitialize" {$PWshAliasName = "Initialize-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "activate" {$PWshAliasName = "Enable-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "logout" {$PWshAliasName = "Disconnect-IPA"}
                    "unapply" {$PWshAliasName = "Unregister-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "metadata" {$PWshAliasName = "Get-IPAMetadata"}
                    "conncheck" {$PWshAliasName = "Test-IPAConnection"}
                    "verify" {$PWshAliasName = "Confirm-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "delentry" {$PWshAliasName = "Remove-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + "Entry"}
                    "rebuild" {$PWshAliasName = "Build-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "apply" {$PWshAliasName = "Publish-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "unapply" {$PWshAliasName = "Undo-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "del" {$PWshAliasName = "Remove-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "defaults" {$PWshAliasName = "Get-IPADefaults" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[1])}
                    "tofiles" {$PWshAliasName = "Set-IPATofiles" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "ds" {$PWshAliasName = "Do-IPADs" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "messages" {$PWshAliasName = "Get-IPAMessages" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "match" {$PWshAliasName = "Search-IPAMatch" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "detach" {$PWshAliasName = "Remove-IPAManaged" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "stage" {$PWshAliasName = "Move-IPADelToStage" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    "tofiles" {$PWshAliasName = "Build-IPAFiles" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                    Default {$PWshAliasName = (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[1]) + "-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0])}
                }
                New-Object psobject -property @{
                    PWshFunctionName = "Invoke-FreeIPAAPI" + (Get-Culture).TextInfo.ToTitleCase($IPAAPIName)
                    PWshAliasName	 = $PWshAliasName
                    CmdletDoc        = $IPAAPIDoc
                }
            }
            3 {
                $TmpAPIName = ($IPAAPIName -split '_')[0]
                $TmpPWSVerb = ($IPAAPIName -split '_')[1]
                switch ($TmpPWSVerb) {
                    "archive" {$PWshAliasName = "Move-IPAToArchive" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                    "fetch" {$PWshAliasName = "Build-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                    "is" {$PWshAliasName = "Test-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                    "was" {$PWshAliasName = "Get-IPAStatus" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                    "mod" {$PWshAliasName = "Set-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                    "retrieve" {$PWshAliasName = "Get-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                    "role" {$PWshAliasName = (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2]) + "-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + "Role"}
                    Default {$PWshAliasName = (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[1]) + "-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                }
                New-Object psobject -property @{
                    PWshFunctionName = "Invoke-FreeIPAAPI" + (Get-Culture).TextInfo.ToTitleCase($IPAAPIName)
                    PWshAliasName	 = $PWshAliasName
                    CmdletDoc        = $IPAAPIDoc
                }
            }
            4 {
                $TmpAPIName = ($IPAAPIName -split '_')[0]
                $TmpPWSVerb = ($IPAAPIName -split '_')[1]
                switch ($TmpPWSVerb) {
                    "disallow" {$PWshAliasName = "Deny-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[3])}
                    "allow" {$PWshAliasName = "Approve-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[3])}
                    "default" {$PWshAliasName = ($IPAAPIName -split '_')[3] + "-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[1]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2])}
                    Default {$PWshAliasName = (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[1]) + "-IPA" + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[0]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[2]) + (Get-Culture).TextInfo.ToTitleCase(($IPAAPIName -split '_')[3])}
                }
                New-Object psobject -property @{
                    PWshFunctionName = "Invoke-FreeIPAAPI" + (Get-Culture).TextInfo.ToTitleCase($IPAAPIName)
                    PWshAliasName	 = $PWshAliasName
                    CmdletDoc        = $IPAAPIDoc
                }
            }      
        }
    }
}
Function Get-IPACmdletBinding {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [Object]$inputSchemaObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false)]
        [ValidateSet("BindingValue", "All", "BindingCondition")]
            [string]$InfoType
    ) 
    process {
        if (!($inputSchemaObject.takes_options) -and !($inputSchemaObject.takes_args)) {
            throw "Input object not valid"
        }
        $Objargs = $inputSchemaObject.takes_args
        $Objoptions = $inputSchemaObject.takes_options
        foreach ($arg in $Objoptions) {
            switch ($InfoType) {
                "BindingValue" { Get-IPACmdletBindingValue $arg }
                "BindingCondition" { Get-IPABindingCondition $arg }
                Default {
                    Get-IPACmdletBindingValue $arg
                    Get-IPABindingCondition $arg
                 }
            }
        }
        foreach ($arg in $Objargs) {
            If ($arg.gettype().fullname -ne "System.String") {
                switch ($InfoType) {
                    "BindingValue" { Get-IPACmdletBindingValue $arg }
                }
            }
        }
    }
}
Function Get-IPACmdletBindingValue {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [Object]$inputSchemaObject
    ) 
    process {
        if (!($inputSchemaObject.cli_name) -and !($inputSchemaObject.cli_metavar)) {
            $inputSchemaObject
            throw "Input object not valid"
        }
        If (!($inputSchemaObject.deprecated) -and ($inputSchemaObject.doc -notlike "deprecated*")) {
            switch ($inputSchemaObject.cli_metavar) {
                "DATETIME" {$variablecontent = "[System.DateTime]" + "$" + $inputSchemaObject.cli_name}
                "INT" {$variablecontent = "[int]" + "$" + $inputSchemaObject.cli_name}
                "FLAG" {$variablecontent = "[switch]" + "$" + $inputSchemaObject.cli_name}
                "BOOL" {$variablecontent = "[switch]" + "$" + $inputSchemaObject.cli_name}
                "PASSWORD" {$variablecontent = "[SecureString]" + "$" + $inputSchemaObject.cli_name}
                Default {
                    if ($inputSchemaObject.cli_name -eq "password") {
                        $variablecontent = "[SecureString]" + "$" + $inputSchemaObject.cli_name
                    } elseif ($inputSchemaObject.multivalue) {
                        $variablecontent = "[String[]]" + "$" + $inputSchemaObject.cli_name
                    } else {
                        $variablecontent = "[String]" + "$" + $inputSchemaObject.cli_name
                    }
                }
            }
            if ($inputSchemaObject.pattern) {
                $validation = '[ValidatePattern(' + '"' + $inputSchemaObject.pattern + '")]'
            } elseif ($inputSchemaObject.values) {
                $validation = '[ValidateSet(' + (($inputSchemaObject.values | ForEach-Object {'"{0}"' -f $_}) -join ",") + ')]'
            } else {
                if ($inputSchemaObject.cli_metavar -ne "FLAG") {
                    $validation = "[ValidateNotNullOrEmpty()]"
                }
            }
            if (($inputSchemaObject.cli_metavar -eq "BOOL") -or ($inputSchemaObject.cli_metavar -eq "FLAG")) {
                $parameterval = "[parameter(Mandatory=" + "$" + "false)]"
            } elseif ($inputSchemaObject.required -and !($inputSchemaObject.default)) {
                $parameterval = "[parameter(Mandatory=" + "$" + "true)]"
            } else {
                $parameterval = "[parameter(Mandatory=" + "$" + "false)]"
            }
            New-Object psobject -property @{
                Parameter		= $parameterval
                Validation	    = $validation
                Variableandtype = $variablecontent
                APIParam        = $inputSchemaObject.name
                Help            = $inputSchemaObject.doc
                Variable        = $inputSchemaObject.cli_name
            }
        }
    }
}
Function Get-IPABindingCondition {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [Object]$inputSchemaObject
    ) 
    process {
        if (!($inputSchemaObject.cli_name) -and !($inputSchemaObject.cli_metavar)) {
            $inputSchemaObject
            throw "Input object not valid"
        }
        switch ($inputSchemaObject.cli_metavar) {
            "DATETIME" { $variablecondition = "       if (`$" + $inputSchemaObject.cli_name + ") { `$ObjParams | Add-Member -NotePropertyName " + $inputSchemaObject.name + " -NotePropertyValue " + "$" + $inputSchemaObject.cli_name + " }" }
            "INT" { $variablecondition = "       if (`$" + $inputSchemaObject.cli_name + ") { `$ObjParams | Add-Member -NotePropertyName " + $inputSchemaObject.name + " -NotePropertyValue " + "$" + $inputSchemaObject.cli_name + " }" }
            "FLAG" { $variablecondition = "       if (`$" + $inputSchemaObject.cli_name + ".IsPresent) { `$ObjParams | Add-Member -NotePropertyName " + $inputSchemaObject.name + " -NotePropertyValue " + "`$true" + " }" }
            "BOOL" { $variablecondition = "       if (`$" + $inputSchemaObject.cli_name + ".IsPresent) { `$ObjParams | Add-Member -NotePropertyName " + $inputSchemaObject.name + " -NotePropertyValue " + "`$true" + " }" }
            Default {
                if ($inputSchemaObject.cli_name -eq "version") {
                    $variablecondition = ""
                } else {
                    $variablecondition = "       if (`$" + $inputSchemaObject.cli_name + ") { `$ObjParams | Add-Member -NotePropertyName " + $inputSchemaObject.name + " -NotePropertyValue " + "$" + $inputSchemaObject.cli_name + " }"
                }
            }
        }
        New-Object psobject -property @{
            OptionCondition = $variablecondition
            APIParam        = $inputSchemaObject.name
            Variable        = $inputSchemaObject.cli_name
        }
    }
}
Function Invoke-FreeIPAAPIJson_Metadata {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [String]$ObjName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [String]$MethodName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [String]$Object,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [String]$Method,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [String]$Command,
        [parameter(Mandatory=$false)]
            [switch]$FullResultsOutput
    )
    process {
        $JsonMetadataParams = New-Object psobject -property @{
            version = $global:FreeIPAAPIServerConfig.ClientVersion
        }
        if ($Object) {
            $JsonMetadataParams | Add-Member -NotePropertyName object -NotePropertyValue $Object
        }
        if ($Method) {
            $JsonMetadataParams | Add-Member -NotePropertyName method -NotePropertyValue $Method
        }
        if ($Command) {
            $JsonMetadataParams | Add-Member -NotePropertyName command -NotePropertyValue $Command
        }
        $JsonMetadataObject = New-Object psobject -property @{
            id		= "0"
            method	= "json_metadata/1"
            params  = @(@($ObjName,$MethodName),$JsonMetadataParams)
        }
        if (!($FullResultsOutput.IsPresent)) {
            (Invoke-FreeIPAAPI $JsonMetadataObject).result
        } else {
            Invoke-FreeIPAAPI $JsonMetadataObject
        }
    }
}
Function Invoke-FreeIPAAPISessionLogout {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [parameter(Mandatory=$false)]
        [switch]$FullResultsOutput
    )
    process {
        $SessionLogoutParams = New-Object psobject -property @{
            version = $global:FreeIPAAPIServerConfig.ClientVersion
        }
        $SessionLogoutObject = New-Object psobject -property @{
            id		= 0
            method	= "session_logout/1"
            params  = @(@(),$SessionLogoutParams)
        }
        if (!($FullResultsOutput.IsPresent)) {
            (Invoke-FreeIPAAPI $SessionLogoutObject).result.result
        } else {
            Invoke-FreeIPAAPI $SessionLogoutObject
        }
    }
}
Function Publish-IPAModule {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [string]$IPASchemaRef,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [string]$IPAEnvRef,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [string]$IPAModuleFile,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [string]$BuilderName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [string]$Version,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [string]$VersionComment
    )
    $script:BuildingDate = get-date
    $buildtimestamp = $script:BuildingDate.Ticks.ToString()
    $script:PwshModuleTemplate = join-path (Get-ScriptDirectory) "Manage-FreeIPA_Module_Template.file"
    $script:PwshManifestTemplate = join-path (Get-ScriptDirectory) "Manage-FreeIPA_Mainfest_Template.file"
    If (!($IPASchemaRef)) {
        $IPASchemaRef = join-path (Get-ScriptDirectory) "IPAschema.xml"
    }
    If (!($IPAEnvRef)) {
        $IPAEnvRef = join-path (Get-ScriptDirectory) "IPAenv.xml"
    }
    If (!($IPAModuleFile)) {
        $IPAModuleFile = "Manage-FreeIPA_Build_" + $buildtimestamp + ".psm1"
        $IPAModuleFile = join-path (Get-ScriptDirectory) $IPAModuleFile
        $IPAManifestFile = "Manage-FreeIPA_Build_" + $buildtimestamp + ".psd1"
        $IPAManifestFile = join-path (Get-ScriptDirectory) $IPAManifestFile
    } else {
        $IPAManifestFile = $IPAModuleFile.replace(".psm1",".psd1")
    }
    If (!(test-path $IPASchemaRef)) {
        throw "IPA Schema file does not exist."
    }
    If (!(test-path $IPAEnvRef)) {
        throw "IPA Env file does not exist."
    }
    If (!(test-path $script:PwshModuleTemplate) -or !(test-path $script:PwshManifestTemplate)) {
        throw "IPA Powershell module templates missing."
    }
    $script:objEnv = Import-Clixml -Path $IPAEnvRef
    get-content -path $script:PwshModuleTemplate | add-content -path $IPAModuleFile | Out-Null
    get-content -path $script:PwshManifestTemplate | add-content -path $IPAManifestFile | Out-Null
    $TMPManifestContent = (get-content -path $IPAManifestFile).replace("%builddate%",($script:BuildingDate.ToShortDateString()))
    $TMPModuleContent = (get-content -path $IPAModuleFile).replace("%builddate%",($script:BuildingDate.ToShortDateString()))
    if (($script:objEnv.api_version) -and ($script:objEnv.jsonrpc_uri)) {
        $TMPModuleContent = $TMPModuleContent.replace("%api_version%",$script:objEnv.api_version)
        $TMPModuleContent = $TMPModuleContent.replace("%jsonrpc_uri%",($script:objEnv.jsonrpc_uri -replace ("/ipa/json","")))
    } else {
        throw "API Version missing in IPA Env file"
    }
    If ($BuilderName) {
        $TMPModuleContent = $TMPModuleContent.replace("%buildername%",$BuilderName)
        $TMPManifestContent = $TMPManifestContent.replace("%buildername%",$BuilderName)
    } Else {
        $TMPModuleContent = $TMPModuleContent.replace("%buildername%","N/A")
        $TMPManifestContent = $TMPManifestContent.replace("%buildername%","N/A")
    }
    If ($Version) {
        $TMPModuleContent = $TMPModuleContent.replace("%version%",$Version)
        $TMPManifestContent = $TMPManifestContent.replace("%version%",$Version)
    } Else {
        $TMPModuleContent = $TMPModuleContent.replace("%version%","0-N/A")
        $TMPManifestContent = $TMPManifestContent.replace("%version%","0-N/A")
    }
    If ($VersionComment) {
        $TMPModuleContent = $TMPModuleContent.replace("%versioncomment%",$VersionComment)
        $TMPManifestContent = $TMPManifestContent.replace("%versioncomment%",$VersionComment)
    } Else {
        $TMPModuleContent = $TMPModuleContent.replace("%versioncomment%","N/A")
        $TMPManifestContent = $TMPManifestContent.replace("%versioncomment%","N/A")
    }
    $TMPModuleContent | set-content -path $IPAModuleFile | out-null
    $TMPModuleContent = $null
    $script:IPACmdlandAlias = @()
    if (test-path $IPASchemaRef) {
        $script:ObjSchema = Import-Clixml -Path $IPASchemaRef
        $Script:APIsName = ($script:ObjSchema | Get-Member -Type Property,NoteProperty | Select-Object -Property Name).name
        [System.Double]$Script:ProgressCount = 0
        Write-Information "$($Script:APIsName.count) APIs found in FreeIPA Schema"
        Write-Information "Starting generation of Powershell Code for $($Script:APIsName.count) functions" 
        foreach ($APIName in $Script:APIsName) {
            $Script:ProgressCount = $Script:ProgressCount + 1
            Write-Progress -Activity "Building PowerShell Code Function in Progress" -Status "Building code and bindings for $($APIName) API" -PercentComplete (($Script:ProgressCount/$Script:APIsName.count)*100)
            $script:IPACmdlandAlias += Get-IPAPCmdletName $script:ObjSchema."$($APIName)"
            $APINameBindings = Get-IPACmdletBinding -InfoType "BindingValue" -inputSchemaObject $script:ObjSchema."$($APIName)"
            $APIBindingConditions = Get-IPACmdletBinding -InfoType "BindingCondition" -inputSchemaObject $script:ObjSchema."$($APIName)"
            ## Start Function
            ## Function Help Header
            add-content -path $IPAModuleFile -Value "function Invoke-FreeIPAAPI$($APIName) {
        <#
            .DESCRIPTION"
            if ($script:ObjSchema.$APINAME.doc) {
                add-content -path $IPAModuleFile -Value "       $($script:ObjSchema.$APINAME.doc.replace('--','-'))"
            }
            foreach ($Binding in $APINameBindings) {
                add-content -path $IPAModuleFile -Value "       .PARAMETER $($Binding.Variable)"
                if ($Binding.Help) {
                    add-content -path $IPAModuleFile -Value "       $($Binding.Help.replace('--','-'))"
                }
            }
            add-content -path $IPAModuleFile -Value "    #>"
            ## Function Param Header
            add-content -path $IPAModuleFile -Value "    [CmdletBinding()]
        [OutputType([psobject])]
            Param("
            foreach ($Binding in $APINameBindings) {
                add-content -path $IPAModuleFile -Value "               $($Binding.Parameter)
                    $($Binding.Validation)"
                $line = "                " + $Binding.Variableandtype + ","
                add-content -path $IPAModuleFile -Value $line
            }
            add-content -path $IPAModuleFile -Value "               [parameter(Mandatory=`$false)]
                    [switch]`$FullResultsOutput"
            add-content -path $IPAModuleFile -Value "           )"
            ## Function body
            add-content -path $IPAModuleFile -Value "    process {"
            add-content -path $IPAModuleFile -Value "        If (`$version) {
                `$ObjParams = New-Object psobject -property @{
                    version = `$version
                }
            } else {
                `$ObjParams = New-Object psobject -property @{
                    version = `$global:FreeIPAAPIServerConfig.ClientVersion
                }
            }"
            foreach ($Binding in $APINameBindings) {
                if ($Binding.Variableandtype -like "*SecureString*") {
                    $line = "       if ($" + $Binding.variable + ") { [string]$" + $Binding.variable + " = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($" + $Binding.variable + "))}"
                    add-content -path $IPAModuleFile -Value $line
                }
            }
            foreach ($condition in $APIBindingConditions) {
                add-content -path $IPAModuleFile -Value $condition.OptionCondition
            }
            if ($script:ObjSchema."$($APIName)".takes_args.cli_name) {
                $argparams =  ($script:ObjSchema."$($APIName)".takes_args.cli_name | ForEach-Object {'${0}' -f $_}) -join ","
            } else {
                $argparams = ""
            }
            add-content -path $IPAModuleFile -Value "        `$JsonObject = New-Object psobject -property @{
                id		= 0
                method	= `"$($APIName)/1`"
                params  = @(@($($argparams)),`$ObjParams)
            }"
            add-content -path $IPAModuleFile -Value "        if (!(`$FullResultsOutput.IsPresent)) {
                (Invoke-FreeIPAAPI `$JsonObject).result.result
            } else {
                Invoke-FreeIPAAPI `$JsonObject
            }"
            add-content -path $IPAModuleFile -Value "    }"
            add-content -path $IPAModuleFile -Value "}"
            ## End of Function
        }
        ## Create Powershell Alias
        foreach ($cmdlet in $IPACmdlandAlias) {
            if ($cmdlet.CmdletDoc) {
                $line = "New-alias -Name $($cmdlet.PWshAliasName) -Value $($cmdlet.PWshFunctionName) -Description " + '"' + "$(($cmdlet.CmdletDoc.split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries))[0])" + '"'
            } else {
                $line = "New-alias -Name $($cmdlet.PWshAliasName) -Value $($cmdlet.PWshFunctionName)"
            }
            add-content -path $IPAModuleFile -Value $line
        }
        add-content -path $IPAModuleFile -Value 'New-Alias -Name Set-IPACredentials -value Set-FreeIPAAPICredentials -Description "Set your IPA API Credential for authentication purpose if your using non Kerberos authentication"'
        add-content -path $IPAModuleFile -Value 'New-Alias -Name Import-IPACrendentials -Value Import-FreeIPAAPICrendentials -Description "Import your IPA API Credential from a local file hosted in your Windows Profile"'
        add-content -path $IPAModuleFile -Value 'New-Alias -Name Set-IPAServerConfig -Value Set-FreeIPAAPIServerConfig -Description "Set IPA server URL and client version"'
        add-content -path $IPAModuleFile -Value 'New-Alias -Name Connect-IPA -value Get-FreeIPAAPIAuthenticationCookie -Description "Get your authentication cookie and save it to be used with all cmdlets/functions"'
        add-content -path $IPAModuleFile -Value 'New-Alias -Name Set-IPAProxy -value Set-FreeIPAProxy -Description "Set a web proxy to be used to connect your FreeIPA server APIs"'
        ## Export Alias and Functions
        $AllFunctions = ($script:IPACmdlandAlias.PWshFunctionName -join ',') + ",Set-FreeIPAAPICredentials,Import-FreeIPAAPICrendentials,Set-FreeIPAAPIServerConfig,Get-FreeIPAAPIAuthenticationCookie,Set-FreeIPAProxy"
        $AllAlias = ($script:IPACmdlandAlias.PWshAliasName -join ',') + ",Set-IPACredentials,Import-IPACrendentials,Set-IPAServerConfig,Connect-IPA,Set-IPAProxy"
        add-content -path $IPAModuleFile -Value "Export-ModuleMember -Function $($AllFunctions)"
        add-content -path $IPAModuleFile -Value "Export-ModuleMember -Alias $($AllAlias)"
        ## Update functions and alias in Manifest
        $ManifestFunctions = ($AllFunctions -split "," | ForEach-Object {"'{0}'" -f $_}) -join ","
        $ManifestAlias = ($AllAlias -split "," | ForEach-Object {"'{0}'" -f $_}) -join ","
        $TMPManifestContent = $TMPManifestContent.replace("%functions%",$ManifestFunctions)
        $TMPManifestContent = $TMPManifestContent.replace("%alias%",$ManifestAlias)
        $TMPManifestContent | set-content -path $IPAManifestFile | out-null
        # Output object for summary
        New-Object psobject -Property @{
            BuildingDate = $script:BuildingDate
            ModuleFileName = $IPAModuleFile
            ManifestFileName = $IPAManifestFile
            Version = $Version
            Changelog = $VersionComment
            Builder = $BuilderName
            Functions = $AllFunctions -split ","
            Alias = $AllAlias -split ","
        }
    }
}
Function Invoke-FreeIPAAPI {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
            [Object]$inputAPIObject
    )
    begin {
        If (!(get-variable FreeIPASession)) {
            throw "Please use Get-FreeIPAAPIAuthenticationCookie function first to get an authentication cookie"
        }
    } process {
        try {
            $json = $inputAPIObject | ConvertTo-Json -Depth 3
            Write-Verbose -message $json
        } catch {
            write-error -message "Not able to convert input object to json"
        }
        try {
            if ($json) {
              if ($global:FreeIPAProxyParams) {
			  $params = $global:FreeIPAProxyParams.clone()
			  if (!$params.UseBasicParsing){$params.add('UseBasicParsing', $true)}
		      } Else {
			    $params = @{}
			    $params.add('UseBasicParsing', $true)
		      }
              $params.add('URI', "$($global:FreeIPAAPIServerConfig.ServerURL)/ipa/session/json")
              $params.add('WebSession', $global:FreeIPASession)
              $params.add('Body',$json)
              $params.add('Method','POST')
              $params.add('ContentType','application/json')
              $params.add('Headers',@{"Referer"="$($global:FreeIPAAPIServerConfig.ServerURL)/ipa/session/json"})
                Invoke-RestMethod @params
            }            
        } catch {
            write-verbose -message "Error Type: $($_.Exception.GetType().FullName)"
			write-verbose -message "Error Message: $($_.Exception.Message)"
			write-verbose -message "HTTP error code:$($_.Exception.Response.StatusCode.Value__)"
			write-verbose -message "HTTP error message:$($_.Exception.Response.StatusDescription)"
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
}
Function Set-FreeIPAProxy {
	<#
	  .SYNOPSIS 
	  Set an internet proxy to use FreeIPA web api
  
	  .DESCRIPTION
	  Set an internet proxy to use FreeIPA web api

	  .PARAMETER DirectNoProxy
	  -DirectNoProxy
	  Remove proxy and configure FreeIPA powershell functions to use a direct connection
	
	  .PARAMETER Proxy
	  -Proxy{Proxy}
	  Set the proxy URL

	  .PARAMETER ProxyCredential
	  -ProxyCredential{ProxyCredential}
	  Set the proxy credential to be authenticated with the internet proxy set

	  .PARAMETER ProxyUseDefaultCredentials
	  -ProxyUseDefaultCredentials
	  Use current security context to be authenticated with the internet proxy set

	  .PARAMETER AnonymousProxy
	  -AnonymousProxy
	  No authentication (open proxy) with the internet proxy set

	  .OUTPUTS
	  none
	  
	  .EXAMPLE
	  Remove Internet Proxy and set a direct connection
	  C:\PS> Set-FreeIPAProxy -DirectNoProxy

	  .EXAMPLE
	  Set Internet Proxy and with manual authentication
	  $credentials = get-credential 
	  C:\PS> Set-FreeIPAProxy -Proxy "http://myproxy:8080" -ProxyCredential $credentials

	  .EXAMPLE
	  Set Internet Proxy and with automatic authentication based on current security context
	  C:\PS> Set-FreeIPAProxy -Proxy "http://myproxy:8080" -ProxyUseDefaultCredentials

	  .EXAMPLE
	  Set Internet Proxy and with no authentication 
	  C:\PS> Set-FreeIPAProxy -Proxy "http://myproxy:8080" -AnonymousProxy
	#>
	[cmdletbinding()]
	Param (
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
		  [switch]$DirectNoProxy,
      [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
          [ValidateScript({$_ -match "(http[s]?)(:\/\/)([^\s,]+)"})]
	      [string]$Proxy,
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
	      [Management.Automation.PSCredential]$ProxyCredential,
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
		  [Switch]$ProxyUseDefaultCredentials,
	  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
		  [Switch]$AnonymousProxy
	)
	if ($DirectNoProxy.IsPresent){
		$global:FreeIPAProxyParams = $null
	} ElseIf ($Proxy) {
		$global:FreeIPAProxyParams = @{}
		$FreeIPAProxyParams.Add('Proxy', $Proxy)
		if ($ProxyCredential){
			$FreeIPAProxyParams.Add('ProxyCredential', $ProxyCredential)
			If ($FreeIPAProxyParams.ProxyUseDefaultCredentials) {$FreeIPAProxyParams.Remove('ProxyUseDefaultCredentials')}
		} Elseif ($ProxyUseDefaultCredentials.IsPresent){
			$FreeIPAProxyParams.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
			If ($FreeIPAProxyParams.ProxyCredential) {$FreeIPAProxyParams.Remove('ProxyCredential')}
		} ElseIf ($AnonymousProxy.IsPresent) {
			If ($FreeIPAProxyParams.ProxyUseDefaultCredentials) {$FreeIPAProxyParams.Remove('ProxyUseDefaultCredentials')}
			If ($FreeIPAProxyParams.ProxyCredential) {$FreeIPAProxyParams.Remove('ProxyCredential')}
		}
	}
}
Function Set-FreeIPAAPICredentials {
    [cmdletbinding()]
    Param (
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]
          [SecureString]$AdminLogin,
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]
          [SecureString]$AdminPassword,
      [parameter(Mandatory=$false)]
          [switch]$Remove,
      [parameter(Mandatory=$false)]
          [switch]$EncryptKeyInLocalFile,
      [parameter(Mandatory=$false)]
      [ValidateNotNullOrEmpty()]
          [string]$ConfigName,
      [parameter(Mandatory=$false)]
      [ValidateNotNullOrEmpty()]
          [securestring]$MasterPassword
    )
    if ($Remove.IsPresent) {
      $global:FreeIPAAPICredentials = $Null
    } Else {
        $global:FreeIPAAPICredentials = @{
            user = $AdminLogin
            password = $AdminPassword
        }
      If ($EncryptKeyInLocalFile.IsPresent) {
          If (!$MasterPassword -or !$AdminPassword) {
              Write-warning "Please provide a valid Master Password to protect the credential storage on disk and a valid credential"
              throw 'no credential or master password'
          } Else {
              $SaltBytes = New-Object byte[] 32
              $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
              $RNG.GetBytes($SaltBytes)
              $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword
              $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
              $KeyBytes  = $Rfc2898Deriver.GetBytes(32)
              $EncryptedPass = $AdminPassword | ConvertFrom-SecureString -key $KeyBytes
              $EncryptedLogin = $AdminLogin | ConvertFrom-SecureString -key $KeyBytes
              $ObjConfigFreeIPA = @{
                  Salt = $SaltBytes
                  EncryptedAdminSecret = $EncryptedPass
                  EncryptedAdminAccount = $EncryptedLogin
              }
              $FolderName = 'Manage-FreeIPA'
              if ($ConfigName) {
                  $ConfigName = "Manage-FreeIPA-$($ConfigName).xml"
              } else {
                  $ConfigName = 'Manage-FreeIPA.xml'
              }
              if (!$home -and $env:userprofile) {
				  $global:home = $env:userprofile
			  }
              if (!(Test-Path -Path "$($global:home)\$FolderName")) {
                  New-Item -ItemType directory -Path "$($global:home)\$FolderName" | Out-Null
              }
              if (test-path "$($global:home)\$FolderName\$ConfigName") {
                  Remove-item -Path "$($global:home)\$FolderName\$ConfigName" -Force | out-null
              }
              $ObjConfigFreeIPA | Export-Clixml "$($global:home)\$FolderName\$ConfigName"
          }
      }
    }
  }
Function Import-FreeIPAAPICrendentials {
      [CmdletBinding()]
      Param(
          [parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
          [ValidateNotNullOrEmpty()]
            [string]$ConfigName,
          [Parameter(Mandatory=$true)]
          [ValidateNotNullOrEmpty()]
            [securestring]$MasterPassword
      )
      process {
          $FolderName = 'Manage-FreeIPA'
          if ($ConfigName) {
            $ConfigName = "Manage-FreeIPA-$($ConfigName).xml"
          } else {
            $ConfigName = 'Manage-FreeIPA.xml'
          }
          if (!$home -and $env:userprofile) {
            $global:home = $env:userprofile
          }
          if (!(Test-Path "$($global:home)\$($FolderName)\$($ConfigName)")){
              Write-warning 'Configuration file has not been set, Set-FreeIPAAPICredentials to configure the credentials.'
              throw 'error config file not found'
          }
          $ObjConfigFreeIPA = Import-Clixml "$($global:home)\$($FolderName)\$($ConfigName)"
          $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword
          try {
              $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $ObjConfigFreeIPA.Salt
              $KeyBytes  = $Rfc2898Deriver.GetBytes(32)
              $SecStringPass = ConvertTo-SecureString -Key $KeyBytes $ObjConfigFreeIPA.EncryptedAdminSecret
              $SecStringLogin = ConvertTo-SecureString -Key $KeyBytes $ObjConfigFreeIPA.EncryptedAdminAccount
              $global:FreeIPAAPICredentials = @{
                  user = $SecStringLogin
                  password = $SecStringPass
              }
          } catch {
              write-warning "Not able to set correctly your credential, your passphrase my be incorrect"
              write-verbose -message "Error Type: $($_.Exception.GetType().FullName)"
              write-verbose -message "Error Message: $($_.Exception.Message)"
          }
      }
  }
Function Set-FreeIPAAPIServerConfig {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({$_ -match "(http[s]?)(:\/\/)([^\s,]+)"})]
            [String]$URL,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [String]$ClientVersion
    )
    process {
        if ($URL) {
            $global:FreeIPAAPIServerConfig = @{
                ServerURL = $URL
            }
        } else {
            $global:FreeIPAAPIServerConfig = @{
                ServerURL = "https://ipa.demo1.freeipa.org"
            }
        }
        if ($ClientVersion) {
            $global:FreeIPAAPIServerConfig.add('ClientVersion',$ClientVersion)
        } else {
            $global:FreeIPAAPIServerConfig.add('ClientVersion',"2.29")
        }
    }
  }
Function Get-FreeIPAAPIAuthenticationCookie {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({$_ -match "(http[s]?)(:\/\/)([^\s,]+)"})]
            [String]$URL,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [SecureString]$AdminLogin,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
            [SecureString]$AdminPassword,
        [parameter(Mandatory=$false)]
            [switch]$UseCachedURLandCredentials,
        [parameter(Mandatory=$false)]
            [switch]$CloseAllRemoteSession
    )
    if ($CloseAllRemoteSession.IsPresent) {
        Invoke-FreeIPAAPISessionLogout
    } else {
        if (!($UseCachedURLandCredentials.IsPresent)) {
            if ($URL -and $AdminLogin -and $AdminPassword) {
                $global:FreeIPAAPICredentials = @{
                    user = $AdminLogin
                    password = $AdminPassword
                }
                Set-FreeIPAAPIServerConfig -URL $URL

            } else {
                write-warning "if UseCachedURLandCredentials switch is not used URL, AdminLogin, AdminPassword parameters must be used"
                throw 'AdminLogin, AdminPassword parameters must be used'
            }
        }
        try {
            $SecureStringPassToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:FreeIPAAPICredentials.password)
            $SecureStringLoginToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:FreeIPAAPICredentials.user)
            $BSTRCredentials = @{
                user = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringLoginToBSTR)
                password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringPassToBSTR) 
            }            
            if ($global:FreeIPAProxyParams) {
			  $params = $global:FreeIPAProxyParams.clone()
			  if (!$params.UseBasicParsing){$params.add('UseBasicParsing', $true)}
		    } Else {
			  $params = @{}
			  $params.add('UseBasicParsing', $true)
		    }
            $params.add('URI', "$($global:FreeIPAAPIServerConfig.ServerURL)/ipa/session/login_password")
            $params.add('Session', 'FunctionFreeIPASession')
            $params.add('Body',$BSTRCredentials)
            $params.add('Method','POST')
            $FreeIPALogin = Invoke-WebRequest @params
        } catch {
            write-verbose -message "Error Type: $($_.Exception.GetType().FullName)"
			write-verbose -message "Error Message: $($_.Exception.Message)"
			write-verbose -message "HTTP error code:$($_.Exception.Response.StatusCode.Value__)"
			write-verbose -message "HTTP error message:$($_.Exception.Response.StatusDescription)"
            $PSCmdlet.ThrowTerminatingError($PSitem)
        } 
        $global:FreeIPASession = $FunctionFreeIPASession
        $FreeIPALogin
    }
}

New-Alias -Name Get-IPAJsonMetadata -Value Invoke-FreeIPAAPIJson_Metadata -Description "Get metadata information used by IPA API Web browsing page"
New-Alias -Name Connect-IPA -value Get-FreeIPAAPIAuthenticationCookie -Description "Get your authentication cookie and save it to be used with all cmdlets/functions"
New-Alias -Name Disconnect-IPA -value Invoke-FreeIPAAPISessionLogout -Description "Remove your authentication cookie and close remote server session"
New-Alias -Name Get-IPAEnvironment -Value Invoke-FreeIPAAPIEnv -Description "Get all IPA environment information"
New-Alias -Name Set-IPAServerConfig -Value Set-FreeIPAAPIServerConfig -Description "Set IPA server URL and client version"
New-Alias -Name Import-IPACrendentials -Value Import-FreeIPAAPICrendentials -Description "Import your IPA API Credential from a local file hosted in your Windows Profile"
New-Alias -Name Set-IPACredentials -value Set-FreeIPAAPICredentials -Description "Set your IPA API Credential for authentication purpose if your using non Kerberos authentication"
New-Alias -Name Set-IPAProxy -value Set-FreeIPAProxy -Description "Set a web proxy to be used to connect your FreeIPA server APIs"

Export-ModuleMember -Function Invoke-FreeIPAAPIJson_Metadata, Get-FreeIPAAPIAuthenticationCookie, Invoke-FreeIPAAPISessionLogout, Invoke-FreeIPAAPIEnv, Export-IPASchema, Export-IPAEnv, 
                                Publish-IPAModule, Get-IPAPCmdletName, Get-IPACmdletBinding, Get-IPACmdletBindingValue, Get-IPABindingCondition, Set-FreeIPAAPICredentials, Import-FreeIPAAPICrendentials, 
                                Set-FreeIPAAPIServerConfig, Get-ScriptDirectory, Set-FreeIPAProxy
Export-ModuleMember -Alias Get-IPAJsonMetadata, Connect-IPA, Disconnect-IPA, Get-IPAEnvironment, Set-IPAServerConfig, Import-IPACrendentials, Set-IPACredentials, Set-IPAProxy