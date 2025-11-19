# Check if WSL is running
$wslStatus = wsl --status
if ($wslStatus -notmatch "running") {
    Write-Host "Starting WSL..."
    wsl --shutdown
    Start-Sleep -Seconds 5
}

# Install Falco in WSL if not already installed
$falcoCheck = wsl -e bash -c "command -v falco" 2>$null
if (-not $falcoCheck) {
    Write-Host "Installing Falco in WSL..."
    wsl -e bash -c "
    # Add falcosecurity repository
    curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
    echo 'deb https://download.falco.org/packages/deb stable main' | tee -a /etc/apt/sources.list.d/falcosecurity.list
    apt-get update -y
    apt-get install -y falco
    "
}

# Start Falco in WSL
Write-Host "Starting Falco in WSL..."
Start-Process -NoNewWindow -FilePath "wsl" -ArgumentList "-e", "sudo", "service", "falco", "start"

Write-Host "Falco is now running in WSL."
Write-Host "To view Falco logs, run: wsl sudo journalctl -u falco -f"
Write-Host "To stop Falco, run: wsl sudo service falco stop"
