#Requires –Modules ActiveDirectory

<# 
.SYNOPSIS
    A PowerShell module to deploy Active Directory decoy objects.
.DESCRIPTION
    Creates decoy AD users, computers, and groups for deception-based security.
.AUTHOR
    Nikhil Mittal (@nikhil_mitt) 
.Co-Author
    Kvngtheta (@No0BackSappi3)
.LINK
    https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
    https://github.com/samratashok/Deploy-Deception
#>

##################################### Helper Functions #####################################

function Create-DecoyUser {
    <#
    .SYNOPSIS
        Create a decoy user object.
    .DESCRIPTION
        Creates a user object in Active Directory.
    .PARAMETER UserFirstName
        First name of the user.
    .PARAMETER UserLastName
        Last name of the user.
    .PARAMETER Password
        Password for the user.
    .PARAMETER OUDistinguishedName
        DistinguishedName of the OU where the user will be created.
    .EXAMPLE
        Create-DecoyUser -UserFirstName John -UserLastName Doe -Password Pass@123
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$UserFirstName,

        [Parameter(Mandatory)]
        [String]$UserLastName,

        [Parameter(Mandatory)]
        [String]$Password,

        [Parameter()]
        [String]$OUDistinguishedName
    )

    $UserDisplayName = "$UserFirstName$UserLastName"
    Write-Verbose "Creating user: $UserDisplayName"

    try {
        $NewUserParams = @{
            Name              = $UserDisplayName
            AccountPassword   = (ConvertTo-SecureString -AsPlainText $Password -Force)
            SamAccountName    = $UserDisplayName
            Enabled           = $True
            DisplayName       = $UserDisplayName
            PassThru          = $True
        }

        if ($OUDistinguishedName) {
            $NewUserParams["Path"] = $OUDistinguishedName
        }

        New-ADUser @NewUserParams | Select-Object -ExpandProperty SamAccountName
    }
    catch {
        Write-Error "Failed to create user: $_"
    }
}

function Create-DecoyComputer {
    <#
    .SYNOPSIS
        Create a decoy computer object.
    .DESCRIPTION
        Creates a computer object in Active Directory.
    .PARAMETER ComputerName
        Name of the computer.
    .PARAMETER OUDistinguishedName
        DistinguishedName of the OU where the computer will be created.
    .EXAMPLE
        Create-DecoyComputer -ComputerName FakePC
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$ComputerName,

        [Parameter()]
        [String]$OUDistinguishedName
    )

    $DNSHostname = "$ComputerName.$((Get-ADDomain).DNSRoot)"
    Write-Verbose "Creating computer: $DNSHostname"

    try {
        $NewComputerParams = @{
            Name        = $ComputerName
            Enabled     = $True
            DNSHostName = $DNSHostname
            PassThru    = $True
        }

        if ($OUDistinguishedName) {
            $NewComputerParams["Path"] = $OUDistinguishedName
        }

        New-ADComputer @NewComputerParams | Select-Object -ExpandProperty SamAccountName
    }
    catch {
        Write-Error "Failed to create computer: $_"
    }
}

function Create-DecoyGroup {
    <#
    .SYNOPSIS
        Create a decoy group object.
    .DESCRIPTION
        Creates a group object in Active Directory.
    .PARAMETER GroupName
        Name of the group.
    .PARAMETER GroupScope
        Scope of the group (Global, DomainLocal, Universal).
    .EXAMPLE
        Create-DecoyGroup -GroupName "FakeAdmins"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$GroupName,

        [Parameter()]
        [ValidateSet("DomainLocal", "Global", "Universal")]
        [String]$GroupScope = "Global"
    )

    Write-Verbose "Creating group: $GroupName"

    try {
        New-ADGroup -Name $GroupName -GroupScope $GroupScope -PassThru | Select-Object -ExpandProperty SamAccountName
    }
    catch {
        Write-Error "Failed to create group: $_"
    }
}

function Get-ADObjectDetails {
    <#
    .SYNOPSIS
        Retrieve details about an AD object.
    .DESCRIPTION
        Retrieves the SamAccountName, DistinguishedName, and ACL for a given object.
    .PARAMETER Identity
        Identity (username, computer name, or group name) to get details for.
    .EXAMPLE
        Get-ADObjectDetails -Identity "FakeUser"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Identity
    )

    try {
        $ADObject = Get-ADObject -Filter { Name -eq $Identity } -Properties distinguishedName
        if ($ADObject) {
            return @{
                SamAccountName     = $Identity
                DistinguishedName  = $ADObject.distinguishedName
                ACL                = (Get-Acl -Path "AD:\$($ADObject.distinguishedName)")
            }
        }
        else {
            Write-Error "Object not found: $Identity"
        }
    }
    catch {
        Write-Error "Error retrieving object details: $_"
    }
}

function Set-AuditRule {
    <#
    .SYNOPSIS
        Set auditing rules on an AD object.
    .DESCRIPTION
        Configures SACL auditing for a specified AD object.
    .PARAMETER Identity
        SamAccountName of the object to set SACL for.
    .PARAMETER Principal
        The user or group for which auditing is turned on.
    .PARAMETER Right
        The right to audit (e.g., ReadProperty, WriteDacl, etc.).
    .PARAMETER AuditFlag
        Audit for success or failure.
    .EXAMPLE
        Set-AuditRule -Identity "FakeUser" -Principal "Everyone" -Right "ReadProperty"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Identity,

        [Parameter(Mandatory)]
        [String]$Principal,

        [Parameter()]
        [ValidateSet("GenericAll", "GenericRead", "GenericWrite", "ReadControl", "ReadProperty", "WriteDacl", "WriteOwner", "WriteProperty")]
        [String]$Right = "ReadProperty",

        [Parameter()]
        [ValidateSet("Success", "Failure")]
        [String]$AuditFlag = "Success"
    )

    $objectDetails = Get-ADObjectDetails -Identity $Identity
    if (-not $objectDetails) {
        Write-Error "Could not retrieve object details for $Identity."
        return
    }

    try {
        $ACL = $objectDetails.ACL
        $SID = New-Object System.Security.Principal.NTAccount($Principal)
        $AuditRule = New-Object DirectoryServices.ActiveDirectoryAuditRule($SID, $Right, $AuditFlag)

        Write-Verbose "Setting audit rule for $Identity: $Principal - $Right ($AuditFlag)"
        $ACL.AddAuditRule($AuditRule)
        Set-Acl -Path "AD:\$($objectDetails.DistinguishedName)" -AclObject $ACL
    }
    catch {
        Write-Error "Failed to set audit rule: $_"
    }
}

################################## End of Helper Functions #################################

