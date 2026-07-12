$password = 'not-a-real-password' | ConvertTo-SecureString -AsPlainText -Force

Configuration RiskyWindowsFleet {
    Import-DscResource -ModuleName PSDscResources

    Node '*' {
        Script Bootstrap {
            GetScript = { @{ Result = 'unknown' } }
            TestScript = { $false }
            SetScript = { Start-Process 'installer.exe' -Wait }
        }

        File RemoveLegacy {
            DestinationPath = 'C:\ProgramData\legacy'
            Ensure = 'Absent'
        }

        Group LocalAdmins {
            GroupName = 'Administrators'
            MembersToInclude = 'CONTOSO\Deployers'
            PsDscRunAsCredential = $domainAdmin
        }

        xRemoteFile Agent {
            Uri = 'http://example.invalid/agent.msi'
            DestinationPath = 'C:\Temp\agent.msi'
        }
    }
}

[DSCLocalConfigurationManager()]
Configuration RiskyLcm {
    Node '*' {
        Settings {
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
            AllowModuleOverwrite = $true
        }
        ConfigurationRepositoryWeb PullServer {
            ServerURL = 'http://dsc.example.invalid/PSDSCPullServer.svc'
            RegistrationKey = 'not-a-real-registration-key'
        }
    }
}

@{
    AllNodes = @(
        @{
            NodeName = '*'
            PSDscAllowPlainTextPassword = $true
        }
    )
}
