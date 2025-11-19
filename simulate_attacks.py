import os
import subprocess
import time
from datetime import datetime
import random

def log_activity(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def simulate_shell_execution():
    """Simulate suspicious shell execution"""
    log_activity("Simulating suspicious shell execution...")
    shells = ["bash", "sh", "dash"]
    for shell in shells:
        try:
            # This should trigger the Suspicious_Shell_Execution rule
            subprocess.run([shell, "-c", "echo 'This is a test command'"])
            log_activity(f"Executed command using {shell}")
        except Exception as e:
            log_activity(f"Error executing {shell}: {str(e)}")

def simulate_crypto_mining():
    """Simulate crypto mining activity"""
    log_activity("Simulating crypto mining activity...")
    mining_commands = [
        "echo 'Starting miner with --url pool.example.com --user x'",
        "echo 'Mining XMR with xmrig'",
        "echo 'Using mining pool: xmr.pool.minergate.com:45700'"
    ]
    for cmd in mining_commands:
        try:
            # These commands should trigger the Crypto_Mining_Activity rule
            subprocess.run(cmd, shell=True)
            log_activity(f"Executed: {cmd}")
        except Exception as e:
            log_activity(f"Error executing mining command: {str(e)}")

def main():
    log_activity("Starting attack simulation...")
    
    # Run simulations
    simulate_shell_execution()
    time.sleep(1)  # Small delay between simulations
    simulate_crypto_mining()
    
    log_activity("Attack simulation completed! Check your email for Falco alerts.")

if __name__ == "__main__":
    main()
