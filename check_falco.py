import subprocess
import sys

def check_falco_running():
    """Check if Falco is running"""
    try:
        result = subprocess.run(['systemctl', 'is-active', 'falco'], 
                              capture_output=True, text=True)
        if result.returncode == 0 and 'active' in result.stdout.lower():
            print("✅ Falco is running")
            return True
        else:
            print("❌ Falco is not running")
            return False
    except FileNotFoundError:
        print("❌ 'systemctl' command not found. Are you running this on a Linux system?")
        return False

def check_falco_logs():
    """Check Falco logs for any recent activity"""
    try:
        print("\nChecking Falco logs for recent activity...")
        result = subprocess.run(['journalctl', '-u', 'falco', '--since', '5 minutes ago', '--no-pager'],
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            if result.stdout.strip():
                print("Recent Falco log entries:")
                print("-" * 50)
                print(result.stdout)
                print("-" * 50)
            else:
                print("No recent activity in Falco logs.")
        else:
            print("❌ Error checking Falco logs:")
            print(result.stderr)
    except Exception as e:
        print(f"❌ Error checking Falco logs: {str(e)}")

def main():
    print("🔍 Checking Falco status...")
    if not check_falco_running():
        print("\nPlease start Falco before running the simulation:")
        print("  sudo systemctl start falco")
        sys.exit(1)
    
    check_falco_logs()
    
    print("\nTo run the attack simulation, execute:")
    print("  python simulate_attacks.py")

if __name__ == "__main__":
    main()
