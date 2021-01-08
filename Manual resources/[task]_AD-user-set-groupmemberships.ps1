HID-Write-Status -Message "Groups to add: $groupsToAdd" -Event Information

try {
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
    HID-Write-Status -Message "Found AD user [$userPrincipalName]" -Event Information
    HID-Write-Summary -Message "Found AD user [$userPrincipalName]" -Event Information
} catch {
    HID-Write-Status -Message "Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to find AD user [$userPrincipalName]" -Event Failed
}

if($groupsToAdd -ne "[]"){
    try {
        $groupsToAddJson =  $groupsToAdd | ConvertFrom-Json
        
        Add-ADPrincipalGroupMembership -Identity $adUser -MemberOf $groupsToAddJson.name -Confirm:$false
        HID-Write-Status -Message "Finished adding AD user [$userPrincipalName] to AD groups $groupsToAdd" -Event Success
        HID-Write-Summary -Message "Successfully added AD user [$userPrincipalName] to AD groups $groupsToAdd" -Event Success
    } catch {
        HID-Write-Status -Message "Could not add AD user [$userPrincipalName] to AD groups $groupsToAdd. Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Failed to add AD user [$userPrincipalName] to AD groups $groupsToAdd" -Event Failed
    }
}
