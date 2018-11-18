if ((get-module).name -notcontains "Build-FreeIPAModule") {
    import-module "C:\Users\tst\Documents\GitHub\Build-FreeIPAModule\Build-FreeIPAModule.psd1"
}
Set-FreeIPAAPICredentials -AdminLogin (ConvertTo-SecureString -String "admin" -AsPlainText -Force) -AdminPassword (ConvertTo-SecureString -String "adminpass" -AsPlainText -Force)
Set-FreeIPAAPIServerConfig -URL https://yourIPA.domain.tld
Get-FreeIPAAPIAuthenticationCookie -UseCachedURLandCredentials
Export-IPAEnv
Export-IPASchema
Publish-IPAModule -IPASchemaRef "C:\Users\tst\Documents\GitHub\Build-FreeIPAModule\IPAschema.xml" -IPAEnvRef "C:\Users\tst\Documents\GitHub\Build-FreeIPAModule\IPAenv.xml" -BuilderName "You" -Version "1.0" -VersionComment "Your First Release"
