# Test-side oracle only; never writes the user's settings.
$ErrorActionPreference='Stop';$values=@{}
$key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Sysinternals\Process Monitor')
if($key){try{foreach($name in $key.GetValueNames()){$value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);$bytes=if($value -is [byte[]]){$value}else{[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Compress))};$values[$name]=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))}}finally{$key.Dispose()}}
$values|ConvertTo-Json -Compress
