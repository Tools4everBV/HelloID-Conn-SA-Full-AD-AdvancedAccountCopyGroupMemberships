# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ADusersSearchOU
$tmpName = @'
ADusersSearchOU
'@ 
$tmpValue = @'
[{ "OU": "OU=Disabled Users,OU=HelloID Training,DC=veeken,DC=local"},{ "OU": "OU=Users,OU=HelloID Training,DC=veeken,DC=local"},{"OU": "OU=External,OU=HelloID Training,DC=veeken,DC=local"}]
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}
<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "AD-group-generate-table-advanced-copy-groupmemberships" #>
$tmpPsScript = @'
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
    Write-Error "Error searching for AD groups. Error: $($_.Exception.Message)"
}
'@ 
$tmpModel = @'
[{"key":"percentage","type":0},{"key":"display","type":0},{"key":"counter","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"minPercentage","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"orderBy","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"orderType","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"filterAttributes","type":0,"options":1}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
AD-group-generate-table-advanced-copy-groupmemberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "AD-group-generate-table-advanced-copy-groupmemberships" #>

<# Begin: DataSource "AD-user-generate-table-attributes-basic-advanced-copy-groupmemberships" #>
$tmpPsScript = @'
try {
    $userPrincipalName = $dataSource.selectedUser.UserPrincipalName
    Write-Information "Searching AD user [$userPrincipalName]"
     
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } -Properties displayname, samaccountname, userPrincipalName, mail, employeeID, Enabled | Select-Object displayname, samaccountname, userPrincipalName, mail, employeeID, Enabled
    Write-Information -Message "Finished searching AD user [$userPrincipalName]"
     
    foreach($tmp in $adUser.psObject.properties)
    {
        $returnObject = @{name=$tmp.Name; value=$tmp.value}
        Write-Output $returnObject
    }
     
    Write-Information "Finished retrieving AD user [$userPrincipalName] basic attributes"
} catch {
    Write-Error "Error retrieving AD user [$userPrincipalName] basic attributes. Error: $($_.Exception.Message)"
}
'@ 
$tmpModel = @'
[{"key":"value","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
AD-user-generate-table-attributes-basic-advanced-copy-groupmemberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "AD-user-generate-table-attributes-basic-advanced-copy-groupmemberships" #>

<# Begin: DataSource "AD-user-generate-table-filters-advanced-copy-groupmemberships" #>
$tmpStaticValue = @'
[{"name":"Company","value":"company","selected":0},{"name":"Department","value":"department","selected":0},{"name":"Jobtitle","value":"title","selected":1}]
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"selected","type":0},{"key":"value","type":0}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
AD-user-generate-table-filters-advanced-copy-groupmemberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "2" -DatasourceStaticValue $tmpStaticValue -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "AD-user-generate-table-filters-advanced-copy-groupmemberships" #>

<# Begin: DataSource "AD-user-generate-table-groupmemberships-advanced-copy-groupmemberships" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"counter","type":0},{"key":"display","type":0},{"key":"percentage","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
AD-user-generate-table-groupmemberships-advanced-copy-groupmemberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "AD-user-generate-table-groupmemberships-advanced-copy-groupmemberships" #>

<# Begin: DataSource "AD-user-generate-table-wildcard-advanced-copy-groupmemberships" #>
$tmpPsScript = @'
try {
    $searchValue = $dataSource.searchUser
    $searchQuery = "*$searchValue*"
    $searchOUs = $ADusersSearchOU
     
     
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        return
    }else{
        Write-Information "SearchQuery: $searchQuery"
        Write-Information "SearchBase: $searchOUs"
         
        $ous = $searchOUs | ConvertFrom-Json
        $users = foreach($item in $ous) {
            Get-ADUser -Filter {Name -like $searchQuery -or DisplayName -like $searchQuery -or userPrincipalName -like $searchQuery -or mail -like $searchQuery} -SearchBase $item.ou -properties SamAccountName, displayName, UserPrincipalName, Description, company, Department, Title
        }
         
        $users = $users | Sort-Object -Property DisplayName
        $resultCount = @($users).Count
        Write-Information "Result count: $resultCount"
         
        if($resultCount -gt 0){
            foreach($user in $users){
                $returnObject = @{SamAccountName=$user.SamAccountName; displayName=$user.displayName; UserPrincipalName=$user.UserPrincipalName; Description=$user.Description; Company=$user.company; Department=$user.Department; Title=$user.Title;}
                Write-Output $returnObject
            }
        }
    }
} catch {
    $msg = "Error searching AD user [$searchValue]. Error: $($_.Exception.Message)"
    Write-Error $msg
}
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"SamAccountName","type":0},{"key":"Title","type":0},{"key":"Company","type":0},{"key":"Department","type":0},{"key":"displayName","type":0},{"key":"UserPrincipalName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
AD-user-generate-table-wildcard-advanced-copy-groupmemberships
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "AD-user-generate-table-wildcard-advanced-copy-groupmemberships" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AD Account - Advanced copy groupmemberships" #>
$tmpSchema = @"
[{"label":"Target user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search target user account","placeholder":"Username or email address"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true},{"key":"gridUsersTarget","templateOptions":{"label":"Select target user account","required":true,"grid":{"columns":[{"headerName":"DisplayName","field":"displayName"},{"headerName":"UserPrincipalName","field":"UserPrincipalName"},{"headerName":"Company","field":"Company"},{"headerName":"Department","field":"Department"},{"headerName":"Title","field":"Title"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true}]},{"label":"Memberships","fields":[{"key":"gridDetails","templateOptions":{"label":"Basic attributes target user","required":false,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"Value","field":"value"}],"height":350,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsersTarget"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true},{"key":"filterAttributes","templateOptions":{"label":"Find common groupmemberships based on following user attributes","useObjects":true,"useFilter":false,"options":[{"value":"company","text":"Company"},{"value":"department","text":"Department"},{"value":"title","text":"Jobtitle"}],"required":true,"useDataSource":true,"valueField":"value","textField":"name","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[]}},"useDefault":true,"defaultSelectorProperty":"selected"},"type":"multiselect","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true},{"key":"formRow","templateOptions":{},"fieldGroup":[{"key":"orderby","templateOptions":{"label":"Order results by","useObjects":true,"options":[{"value":"percentage","label":"Percentage"},{"value":"name","label":"Group name"}],"required":true},"type":"radio","defaultValue":"percentage","summaryVisibility":"Show","textOrLabel":"label","requiresTemplateOptions":true},{"key":"orderType","templateOptions":{"label":"Order type","useObjects":true,"options":[{"value":"Ascending","label":"Ascending"},{"value":"Descending","label":"Descending"}],"required":true},"type":"radio","defaultValue":"Descending","summaryVisibility":"Show","textOrLabel":"label","requiresTemplateOptions":true},{"key":"minPercentage","templateOptions":{"label":"Minimal percentage","required":true,"min":0,"max":100},"type":"number","defaultValue":"0","summaryVisibility":"Show","requiresTemplateOptions":true}],"type":"formrow","requiresTemplateOptions":true},{"key":"memberships","templateOptions":{"label":"Memberships","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"name","optionDisplayProperty":"display","labelLeft":"Available groups based on user attribute filter","labelRight":"Already member of"},"useFilter":false,"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsersTarget"}},{"propertyName":"minPercentage","otherFieldValue":{"otherFieldKey":"minPercentage"}},{"propertyName":"orderBy","otherFieldValue":{"otherFieldKey":"orderby"}},{"propertyName":"orderType","otherFieldValue":{"otherFieldKey":"orderType"}},{"propertyName":"filterAttributes","otherFieldValue":{"otherFieldKey":"filterAttributes"}}]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsersTarget"}}]}}},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true},{"templateOptions":{},"type":"markdown","summaryVisibility":"Show","body":"*Please note that the execution script only adds new group memberships and does not remove group memberships*","requiresTemplateOptions":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
AD Account - Advanced copy groupmemberships
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
AD Account - Advanced copy groupmemberships
'@
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-balance-scale" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
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
'@; 

	$tmpVariables = @'
[{"name":"groupsToAdd","value":"{{form.memberships.leftToRight.toJsonString}}","secret":false,"typeConstraint":"string"},{"name":"userPrincipalName","value":"{{form.gridUsersTarget.UserPrincipalName}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
AD-user-set-groupmemberships
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-Warning "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
