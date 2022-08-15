$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupsToAdd = $form.memberships.leftToRight
$userPrincipalName = $form.gridUsersTarget.UserPrincipalName

Write-Information "Groups to add: $($groupsToAdd.name)"

try {
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
    Write-Information "Found AD user [$userPrincipalName]"     
} catch {
    Write-Error "Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)"
}

if($groupsToAdd -ne "[]"){
    try {        
        Add-ADPrincipalGroupMembership -Identity $adUser -MemberOf $groupsToAdd.name -Confirm:$false
        Write-Information "Finished adding AD user [$userPrincipalName] to [$($groupsToAdd.name)]"
        $Log = @{
                Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                System            = "ActiveDirectory" # optional (free format text) 
                Message           = "Successfully added AD user [$userPrincipalName] to [$($groupsToAdd.name)]" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $adUser.name # optional (free format text) 
                TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) 
            }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log         
    } catch {
        Write-Information "Failed to add AD user [$userPrincipalName] to [$($groupsToAdd.name)]"
        $Log = @{
                Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                System            = "ActiveDirectory" # optional (free format text) 
                Message           = "Failed to add AD user [$userPrincipalName] to [$($groupsToAdd.name)]" # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $adUser.name # optional (free format text) 
                TargetIdentifier  = $([string]$adUser.SID) # optional (free format text) 
            }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log         
    }
}
