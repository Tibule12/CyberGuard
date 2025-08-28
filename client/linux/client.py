"""
Linux client for CyberGuard System.
Monitors system activity and communicates with the cloud server.
"""

import os
import sys
import time
import logging
import requests
import psutil
import socket
import subprocess
from datetime import datetime
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/cyberguard_client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CyberGuardLinuxClient:
    """Linux client for CyberGuard security system."""
    
    def __init__(self, server_url: str = "http://localhost:8000"):
        self.server_url = server_url
        self.client_id = self._get_client_id()
        self.session = requests.Session()
        self.last_heartbeat = 0
        self.heartbeat_interval = 300  # 5 minutes
        
    def _get_client_id(self) -> str:
        """Get or generate unique client ID."""
        client_id_file = '/etc/cyberguard/client_id.txt'
        
        if os.path.exists(client_id_file):
            try:
                with open(client_id_file, 'r') as f:
                    return f.read().strip()
            except:
                pass
        
        # Generate new client ID
        import uuid
        new_id = str(uuid.uuid4())
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(client_id_file), exist_ok=True)
        
        # Save to file
        try:
            with open(client_id_file, 'w') as f:
                f.write(new_id)
        except:
            pass
        
        return new_id
    
    def get_system_info(self) -> Dict[str, Any]:
        """Collect Linux system information."""
        try:
            return {
                "platform": "linux",
                "hostname": socket.gethostname(),
                "username": os.getenv('USER', 'unknown'),
                "cpu_count": psutil.cpu_count(),
                "total_memory": psutil.virtual_memory().total,
                "disk_usage": {d.mountpoint: psutil.disk_usage(d.mountpoint).percent 
                              for d in psutil.disk_partitions()},
                "boot_time": psutil.boot_time(),
                "process_count": len(psutil.pids()),
                "network_interfaces": self._get_network_info(),
                "linux_distro": self._get_linux_distro(),
                "kernel_version": os.uname().release
            }
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {}
    
    def _get_network_info(self) -> Dict[str, Any]:
        """Get network interface information."""
        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces[interface] = {
                "addresses": [addr.address for addr in addrs],
                "stats": psutil.net_io_counters(pernic=True).get(interface, {})
            }
        return interfaces
    
    def _get_linux_distro(self) -> str:
        """Get Linux distribution information."""
        try:
            # Try to read from /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=', 1)[1].strip().strip('"')
            
            # Fallback to uname
            return f"{os.uname().sysname} {os.uname().release}"
        except:
            return "Unknown Linux Distribution"
    
    def register_client(self) -> bool:
        """Register client with the server."""
        try:
            system_info = self.get_system_info()
            payload = {
                "client_id": self.client_id,
                "platform": "linux",
                "version": "0.1.0",
                "system_info": system_info
            }
            
            response = self.session.post(
                f"{self.server_url}/api/v1/clients/register",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("Client registered successfully")
                return True
            else:
                logger.warning(f"Registration failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to server."""
        try:
            response = self.session.post(
                f"{self.server_url}/api/v1/clients/heartbeat/{self.client_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                self.last_heartbeat = time.time()
                return True
            return False
            
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")
            return False
    
    def scan_system(self) -> Dict[str, Any]:
        """Perform system security scan."""
        try:
            # Collect security-related information
            scan_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "processes": self._scan_processes(),
                "network_connections": self._scan_network(),
                "file_system": self._scan_file_system(),
                "linux_security": self._scan_linux_security()
            }
            
            # Send to server for analysis
            response = self.session.post(
                f"{self.server_url}/api/v1/threats/analyze",
                json=scan_data,
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Scan analysis failed"}
                
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {"error": str(e)}
    
    def _scan_processes(self) -> List[Dict[str, Any]]:
        """Scan running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent']):
            try:
                processes.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "username": proc.info['username'],
                    "memory_usage": proc.info['memory_info'].rss if proc.info['memory_info'] else 0,
                    "cpu_usage": proc.info['cpu_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes
    
    def _scan_network(self) -> List[Dict[str, Any]]:
        """Scan network connections."""
        connections = []
        for conn in psutil.net_connections():
            try:
                connections.append({
                    "fd": conn.fd,
                    "family": conn.family,
                    "type": conn.type,
                    "local_address": conn.laddr,
                    "remote_address": conn.raddr,
                    "status": conn.status,
                    "pid": conn.pid
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return connections
    
    def _scan_file_system(self) -> Dict[str, Any]:
        """Scan file system for suspicious activity."""
        # Check for common suspicious locations
        suspicious_locations = [
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/root",
            "/home/*/Downloads"
        ]
        
        suspicious_files = []
        for location in suspicious_locations:
            if '*' in location:
                # Handle glob patterns
                import glob
                expanded_locations = glob.glob(location)
                for exp_location in expanded_locations:
                    if os.path.exists(exp_location):
                        try:
                            files = os.listdir(exp_location)
                            suspicious_files.extend([
                                os.path.join(exp_location, f) 
                                for f in files 
                                if f.endswith(('.sh', '.py', '.pl'))
                            ])
                        except:
                            continue
            else:
                if os.path.exists(location):
                    try:
                        files = os.listdir(location)
                        suspicious_files.extend([
                            os.path.join(location, f) 
                            for f in files 
                            if f.endswith(('.sh', '.py', '.pl'))
                        ])
                    except:
                        continue
        
        return {
            "suspicious_files": suspicious_files[:10],  # Limit to 10 files
            "recent_changes": [],
            "permission_issues": self._check_file_permissions()
        }
    
    def _check_file_permissions(self) -> List[Dict[str, Any]]:
        """Check for problematic file permissions."""
        issues = []
        critical_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys"
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    stat = os.stat(file_path)
                    # Check if world-writable or has insecure permissions
                    if stat.st_mode & 0o002:  # World-writable
                        issues.append({
                            "file": file_path,
                            "issue": "World-writable file",
                            "permissions": oct(stat.st_mode)[-3:]
                        })
                except:
                    continue
        
        return issues
    
    def _scan_linux_security(self) -> Dict[str, Any]:
        """Scan Linux security settings."""
        try:
            security_info = {}
            
            # Check SELinux/AppArmor status
            if os.path.exists('/usr/sbin/sestatus'):
                selinux = subprocess.run(['sestatus'], capture_output=True, text=True)
                security_info['selinux'] = selinux.stdout.strip() if selinux.returncode == 0 else "unknown"
            elif os.path.exists('/usr/sbin/aa-status'):
                apparmor = subprocess.run(['aa-status'], capture_output=True, text=True)
                security_info['apparmor'] = apparmor.stdout.strip() if apparmor.returncode == 0 else "unknown"
            
            # Check firewall status (iptables/ufw)
            if os.path.exists('/usr/sbin/ufw'):
                ufw = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                security_info['firewall'] = ufw.stdout.strip() if ufw.returncode == 0 else "unknown"
            else:
                iptables = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                security_info['firewall'] = "iptables active" if iptables.returncode == 0 else "no firewall"
            
            # Check for rootkits (basic check)
            security_info['rootkit_check'] = self._check_rootkits()
            
            return security_info
            
        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            return {
                "selinux": "error",
                "apparmor": "error",
                "firewall": "error",
                "rootkit_check": "error"
            }
    
    def _check_rootkits(self) -> str:
        """Basic rootkit check."""
        try:
            # Check for common rootkit indicators
            suspicious_processes = ['rk hunter', 'chkrootkit', 'rkhunter']
            for proc in psutil.process_iter(['name']):
                if any(suspicious in proc.info['name'].lower() for suspicious in suspicious_processes):
                    return "suspicious_process_detected"
            
            return "clean"
        except:
            return "check_failed"
    
    def run(self):
        """Main client loop."""
        logger.info("Starting CyberGuard Linux Client")
        
        # Register client
        if not self.register_client():
            logger.error("Failed to register client. Exiting.")
            return
        
        # Main loop
        while True:
            try:
                # Send heartbeat
                if time.time() - self.last_heartbeat >= self.heartbeat_interval:
                    if not self.send_heartbeat():
                        logger.warning("Heartbeat failed")
                
                # Perform periodic scan (every 30 minutes)
                if int(time.time()) % 1800 == 0:
                    logger.info("Performing system scan...")
                    result = self.scan_system()
                    logger.info(f"Scan result: {result.get('threat_level', 'unknown')}")
                
                time.sleep(60)  # Check every minute
                
            except KeyboardInterrupt:
                logger.info("Client stopped by user")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying

def main():
    """Main function."""
    # Get server URL from command line or environment
    server_url = os.getenv('CYBERGUARD_SERVER', 'http://localhost:8000')
    
    client = CyberGuardLinuxClient(server_url)
    client.run()

if __name__ == "__main__":
    main()
