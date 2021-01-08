try {
    $allGroups = @()
    $userFilter = @()
    $minPercentage = [int]$dataSource.minPercentage
    $orderBy = $dataSource.orderby
    $orderType = $dataSource.orderType
    if($orderType -eq "Descending") {
        $orderDescending = $true
    } else {
        $orderDescending = $false
    }
    
    $filterAttributes = $dataSource.filterAttributes
    
    $title = $dataSource.selectedUser.title
    $department = $dataSource.selectedUser.department
    $company = $dataSource.selectedUser.company
    
    foreach($attr in $filterAttributes) {
        if($attr.value -eq "company") {
            if([string]::IsNullOrEmpty($company) -eq $false) {
                $userFilter += "(Company -eq '$company')"
            }
        }
        
        if($attr.value -eq "department") {
            if([string]::IsNullOrEmpty($department) -eq $false) {
                $userFilter += "(Department -eq '$department')"
            }
        }
        
        if($attr.value -eq "title") {
            if([string]::IsNullOrEmpty($title) -eq $false) {
                $userFilter += "(Title -eq '$title')"
            }
        }
    }
    
    $userQuery = $userFilter -join " -and "
    Write-Information "Search filter: $userQuery"
        
    $users = get-aduser -filter $userQuery -Properties samaccountname
    $userCount = @($users).Count    
    Write-Information "Result count: $userCount"        
    
    foreach($user in $users)
    {
        $memberships = Get-ADPrincipalGroupMembership -Identity $user.samaccountname
        $memberships = $memberships | ? {$_.Name -ne "Domain Users"}
        
        foreach($group in $memberships)
        {
            if($item = $allGroups | Where-Object -filter {$_.name -eq $group.name})
            {            
                $item.counter = $item.counter + 1
                $p = [math]::floor(($item.counter / $userCount) * 100)
                $display = $item.name + " (" + $item.counter + "/" + $userCount + " - " + $p + "%)"
    
                $item.percentage = $p
                $item.display = $display
            } else {
                $p = [math]::floor((1 / $userCount) * 100)
                $display = $group.name + " (1/" + $userCount + " - " + $p + "%)"
                $allGroups += [pscustomobject]@{name = $group.name; counter = 1; percentage = $p; display = $display}
            }
        }
     }
    
    
    $allGroups = $allGroups | Where-Object -filter {$_.percentage -ge $minPercentage-1}
    $allGroups = $allGroups | Sort-Object -property @{expression = $orderBy; Descending = $orderDescending}
    $resultCount = @($allGroups).count
    
    if($resultCount -gt 0) {
        foreach($group in $allGroups)
        {
            $returnObject = @{name="$($group.name)"; counter="$($group.counter)"; percentage="$($group.percentage)";display="$($group.display)"}
            Write-Output $returnObject
        }
    }
} catch {
    Write-Error "Error searching for AD groups. Error: $($_.Exception.Message)" -Event Error
}
