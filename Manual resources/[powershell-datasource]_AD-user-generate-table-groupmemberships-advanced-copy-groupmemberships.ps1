try {
    $userPrincipalName = $dataSource.selectedUser.UserPrincipalName
    Write-Information "Searching AD user [$userPrincipalName]"
     
    if([String]::IsNullOrEmpty($userPrincipalName) -eq $true){
        return
    } else {
        $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
        Write-Information "Found AD user [$userPrincipalName]"
         
        $groups = Get-ADPrincipalGroupMembership $adUser | Select-Object name | Sort-Object name
        $groups = $groups | Where-Object {$_.Name -ne "Domain Users"}
        $resultCount = @($groups).Count
        Write-Information "Groupmembership count: $resultCount"
         
        if($resultCount -gt 0) {
            foreach($group in $groups)
            {
                $returnObject = @{name="$($group.name)";}
                Write-Output $returnObject
            }
        }
    }
} catch {
    Write-Error "Error getting groupmemberships [$userPrincipalName]. Error: $($_.Exception.Message)"
}
