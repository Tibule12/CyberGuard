"""
macOS client for CyberGuard System.
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
        logging.FileHandler(os.path.expanduser('~/Library/Logs/cyberguard_client.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CyberGuardMacClient:
    """macOS client for CyberGuard security system."""
    
    def __init__(self, server_url: str = "http://localhost:8000"):
        self.server_url = server_url
        self.client_id = self._get_client_id()
        self.session = requests.Session()
        self.last_heartbeat = 0
        self.heartbeat_interval = 300  # 5 minutes
        
    def _get_client_id(self) -> str:
        """Get or generate unique client ID."""
        client_id_file = os.path.expanduser('~/Library/Application Support/CyberGuard/client_id.txt')
        
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
        """Collect macOS system information."""
        try:
            return {
                "platform": "macos",
                "hostname": socket.gethostname(),
                "username": os.getenv('USER', 'unknown'),
                "cpu_count": psutil.cpu_count(),
                "total_memory": psutil.virtual_memory().total,
                "disk_usage": {d.mountpoint: psutil.disk_usage(d.mountpoint).percent 
                              for d in psutil.disk_partitions()},
                "boot_time": psutil.boot_time(),
                "process_count": len(psutil.pids()),
                "network_interfaces": self._get_network_info(),
                "macos_version": self._get_macos_version()
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
    
    def _get_macos_version(self) -> str:
        """Get macOS version information."""
        try:
            result = subprocess.run(['sw_vers'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            return "Unknown macOS Version"
        except:
            return "Unknown macOS Version"
    
    def register_client(self) -> bool:
        """Register client with the server."""
        try:
            system_info = self.get_system_info()
            payload = {
                "client_id": self.client_id,
                "platform": "macos",
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
                "macos_security": self._scan_macos_security()
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
            "~/Downloads",
            "~/Library/LaunchAgents",
            "~/Library/LaunchDaemons"
        ]
        
        suspicious_files = []
        for location in suspicious_locations:
            expanded_location = os.path.expanduser(location)
            if os.path.exists(expanded_location):
                try:
                    files = os.listdir(expanded_location)
                    suspicious_files.extend([
                        os.path.join(expanded_location, f) 
                        for f in files 
                        if f.endswith(('.sh', '.plist', '.command'))
                    ])
                except:
                    continue
        
        return {
            "suspicious_files": suspicious_files[:10],  # Limit to 10 files
            "recent_changes": [],
            "permission_issues": []
        }
    
    def _scan_macos_security(self) -> Dict[str, Any]:
        """Scan macOS security settings."""
        try:
            # Check Gatekeeper status
            gatekeeper = subprocess.run(['spctl', '--status'], capture_output=True, text=True)
            gatekeeper_status = gatekeeper.stdout.strip() if gatekeeper.returncode == 0 else "unknown"
            
            # Check SIP status
            sip = subprocess.run(['csrutil', 'status'], capture_output=True, text=True)
            sip_status = sip.stdout.strip() if sip.returncode == 0 else "unknown"
            
            # Check firewall
            firewall = subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'], 
                                    capture_output=True, text=True)
            firewall_status = firewall.stdout.strip() if firewall.returncode == 0 else "unknown"
            
            return {
                "gatekeeper": gatekeeper_status,
                "sip": sip_status,
                "firewall": firewall_status,
                "xprotect": "unknown"  # macOS built-in antivirus
            }
            
        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            return {
                "gatekeeper": "error",
                "sip": "error",
                "firewall": "error",
                "xprotect": "error"
            }
    
    def run(self):
        """Main client loop."""
        logger.info("Starting CyberGuard macOS Client")
        
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
    
    client = CyberGuardMacClient(server_url)
    client.run()

if __name__ == "__main__":
    main()
