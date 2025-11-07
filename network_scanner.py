"""
Network Scanner Module
Thực hiện quét mạng với các giao thức ARP, ICMP, TCP
"""
import socket
import ipaddress
import threading #thêm threading vào để lấy thông tin về luồng (thread)
import time
from typing import List, Dict, Set, Optional, Tuple
from queue import Queue
from datetime import datetime
import subprocess #thêm subprocess vào để lấy thông tin về hệ thống và tiến trình (process)
import platform #thêm platform vào để lấy hệ điều hành
import os #thêm os vào để làm việc với file và đường dẫn
import urllib.request #thêm urllib.request vào để tải file từ internet
import urllib.error #thêm urllib.error vào để xử lý lỗi khi tải file

try:
    from scapy.all import ARP, Ether, srp, ICMP, IP, conf #thêm scapy.all vào để lấy ARP, Ether, srp, ICMP, IP, conf
    from scapy.layers.l2 import getmacbyip #thêm scapy.layers.l2 vào để lấy getmacbyip
    SCAPY_AVAILABLE = True #SCAPY_AVAILABLE là True nếu scapy.all và scapy.layers.l2 có sẵn trong máy
except ImportError: #nếu không nhập được scapy.all và scapy.layers.l2 thì in ra lỗi
    SCAPY_AVAILABLE = False #SCAPY_AVAILABLE là False nếu scapy.all và scapy.layers.l2 không có sẵn trong máy
    print("Cảnh báo: Thư viện Scapy không khả dụng. Chức năng quét ARP sẽ bị vô hiệu hóa.") #in ra lỗi

try:
    import nmap
    NMAP_AVAILABLE = True #NMAP_AVAILABLE là True nếu nmap có sẵn trong máy
except ImportError: #nếu không nhập được nmap thì in ra lỗi
    NMAP_AVAILABLE = False #NMAP_AVAILABLE là False nếu nmap không có sẵn trong máy
    print("Thư viện python-nmap không khả dụng. Chức năng quét cổng (Port scanning) sẽ bị vô hiệu hóa.") #in ra lỗi

try:
    from mac_vendor_lookup import MacLookup #thêm mac_vendor_lookup vào để lấy MacLookup
    MAC_LOOKUP_AVAILABLE = True #MAC_LOOKUP_AVAILABLE là True nếu mac_vendor_lookup có sẵn trong máy
except ImportError: #nếu không nhập được mac_vendor_lookup thì in ra lỗi
    MAC_LOOKUP_AVAILABLE = False #MAC_LOOKUP_AVAILABLE là False nếu mac_vendor_lookup không có sẵn trong máy
    print("Cảnh báo: Thư viện mac-vendor-lookup không khả dụng. Chức năng tra cứu vendor từ MAC sẽ bị vô hiệu hóa.") #in ra lỗi

try:
    import psutil #thêm psutil vào để lấy thông tin về hệ thống và tiến trình (process)
    PSUTIL_AVAILABLE = True #PSUTIL_AVAILABLE là True nếu psutil có sẵn trong máy
except ImportError: #nếu không nhập được psutil thì in ra lỗi
    PSUTIL_AVAILABLE = False #PSUTIL_AVAILABLE là False nếu psutil không có sẵn trong máy
    print("Cảnh báo: Thư viện psutil không khả dụng. Chức năng phát hiện interface mạng sẽ bị vô hiệu hóa.") #in ra lỗi

# Đường dẫn đến file OUI database cục bộ
OUI_DB_PATH = os.path.join(os.path.dirname(__file__), 'oui.csv') #đường dẫn đến file oui.csv trong thư mục hiện tại
OUI_DB_URL = 'https://standards-oui.ieee.org/oui/oui.csv' #URL để tải file oui.csv từ IEEE

class LocalMacLookup:
    """Lớp tra cứu MAC vendor từ cơ sở dữ liệu cục bộ"""
    def __init__(self, csv_path: str):
        """Khởi tạo với đường dẫn đến file CSV cục bộ"""
        self.csv_path = csv_path #đường dẫn đến file CSV
        self.oui_dict = {} #từ điển lưu trữ ánh xạ OUI -> vendor
        self.load_database() #tải cơ sở dữ liệu
    
    def load_database(self):
        """Tải cơ sở dữ liệu OUI từ file CSV cục bộ"""
        if not os.path.exists(self.csv_path): #nếu file không tồn tại thì return
            print(f"File OUI database không tồn tại: {self.csv_path}") #in ra cảnh báo
            return #trả về
        
        try:
            import csv #import csv để đọc file CSV
            loaded_count = 0 #đếm số lượng entries đã tải
            with open(self.csv_path, 'r', encoding='utf-8') as f: #mở file CSV
                reader = csv.reader(f) #tạo CSV reader
                next(reader, None)  # Bỏ qua dòng tiêu đề nếu có
                for row in reader: #vòng lặp qua từng dòng
                    try:
                        # Định dạng IEEE OUI CSV: Registry, Assignment (OUI), Organization Name
                        # Cột 0: Registry (MA-L, MA-M, MA-S, etc.)
                        # Cột 1: Assignment (OUI) - format: 00-1A-2B hoặc 001A2B
                        # Cột 2: Organization Name
                        if len(row) >= 3: #nếu dòng có ít nhất 3 cột (định dạng chuẩn IEEE)
                            oui_prefix = row[1].strip().upper().replace('-', '').replace(':', '').replace(' ', '') #lấy OUI prefix từ cột 1 và chuẩn hóa
                            vendor_name = row[2].strip().strip('"').strip("'") #lấy tên vendor từ cột 2, loại bỏ quotes nếu có
                            if oui_prefix and vendor_name and len(oui_prefix) == 6: #nếu cả hai đều không rỗng và OUI có đúng 6 ký tự
                                self.oui_dict[oui_prefix] = vendor_name #thêm vào từ điển
                                loaded_count += 1 #tăng số lượng entries
                        elif len(row) >= 2: #fallback: nếu chỉ có 2 cột (định dạng đơn giản)
                            oui_prefix = row[0].strip().upper().replace('-', '').replace(':', '').replace(' ', '') #lấy OUI prefix từ cột 0 và chuẩn hóa
                            vendor_name = row[1].strip().strip('"').strip("'") #lấy tên vendor từ cột 1, loại bỏ quotes nếu có
                            if oui_prefix and vendor_name and len(oui_prefix) == 6: #nếu cả hai đều không rỗng và OUI có đúng 6 ký tự
                                self.oui_dict[oui_prefix] = vendor_name #thêm vào từ điển
                                loaded_count += 1 #tăng số lượng entries
                    except Exception as row_error: #nếu có lỗi khi xử lý một dòng
                        continue #bỏ qua dòng này và tiếp tục
            print(f"Đã tải {loaded_count} entries từ cơ sở dữ liệu OUI cục bộ") #in ra số lượng entries đã tải
        except Exception as e: #nếu có lỗi thì in ra lỗi
            print(f"Lỗi khi tải cơ sở dữ liệu OUI từ file cục bộ: {e}") #in ra lỗi
            import traceback #import traceback để in chi tiết lỗi
            traceback.print_exc() #in chi tiết lỗi
    
    def lookup(self, mac: str) -> Optional[str]:
        """Tra cứu vendor từ MAC address
        
        Args:
            mac: Địa chỉ MAC ở bất kỳ định dạng nào (ví dụ: '00:1A:2B:3C:4D:5E', '00-1A-2B-3C-4D-5E', '001A2B3C4D5E')
        
        Returns:
            Tên vendor nếu tìm thấy, None nếu không tìm thấy hoặc có lỗi
        """
        if not mac: #nếu MAC rỗng thì return None
            return None #trả về None
        
        try:
            # Chuẩn hóa MAC address: loại bỏ dấu phân cách và chuyển thành chữ hoa
            mac_clean = mac.strip().replace(':', '').replace('-', '').replace('.', '').replace(' ', '').upper() #chuẩn hóa MAC
            if len(mac_clean) < 6: #nếu MAC quá ngắn thì return None
                return None #trả về None
            
            # Lấy 6 ký tự đầu (OUI prefix)
            oui_prefix = mac_clean[:6] #lấy OUI prefix
            
            # Kiểm tra xem OUI prefix có hợp lệ không (chỉ chứa hex characters)
            if not all(c in '0123456789ABCDEF' for c in oui_prefix): #nếu OUI prefix không hợp lệ
                return None #trả về None
            
            return self.oui_dict.get(oui_prefix, None) #trả về vendor hoặc None
        except Exception as e: #nếu có lỗi thì return None
            return None #trả về None
    
    def reload(self):
        """Tải lại cơ sở dữ liệu từ file"""
        self.oui_dict.clear() #xóa từ điển cũ
        self.load_database() #tải lại cơ sở dữ liệu
    
    def get_statistics(self) -> dict:
        """Lấy thống kê về cơ sở dữ liệu OUI
        
        Returns:
            Dictionary chứa thống kê: {'total_entries': int, 'database_path': str}
        """
        return {
            'total_entries': len(self.oui_dict),
            'database_path': self.csv_path
        }

def download_oui_database(force_update: bool = False) -> bool:
    """Tải cơ sở dữ liệu OUI từ IEEE nếu chưa tồn tại cục bộ hoặc force_update=True"""
    if os.path.exists(OUI_DB_PATH) and not force_update: #nếu file oui.csv đã tồn tại và không force update thì return True
        return True #trả về True
    
    try:
        print(f"Đang tải cơ sở dữ liệu OUI từ IEEE...") #in ra thông báo đang tải
        urllib.request.urlretrieve(OUI_DB_URL, OUI_DB_PATH) #tải file oui.csv từ IEEE và lưu vào đường dẫn cục bộ
        print(f"Đã tải xong cơ sở dữ liệu OUI: {OUI_DB_PATH}") #in ra thông báo đã tải xong
        return True #trả về True
    except urllib.error.URLError as e: #nếu có lỗi khi tải file thì in ra lỗi
        print(f"Lỗi khi tải cơ sở dữ liệu OUI: {e}") #in ra lỗi
        print("Sẽ thử tải lại khi có kết nối Internet.") #in ra thông báo sẽ thử lại
        return False #trả về False
    except Exception as e: #nếu có lỗi khác thì in ra lỗi
        print(f"Lỗi không mong đợi khi tải cơ sở dữ liệu OUI: {e}") #in ra lỗi
        return False #trả về False

class NetworkScanner: #tạo lớp NetworkScanner
    def __init__(self, timeout: float = 1.0, threads: int = 100): #khởi tạo lớp NetworkScanner với timeout (mặc định là 1.0 giây) và số luồng (mặc định là 100 luồng)
        self.timeout = timeout #thời gian timeout
        self.threads = threads #số luồng
        self.scanning = False #trạng thái quét
        self.results = [] #kết quả quét
        self.lock = threading.Lock() #khởi tạo lock
        self.mac_lookup = None #khởi tạo biến mac_lookup
        
        # Khởi tạo MAC lookup với cơ sở dữ liệu cục bộ
        try:
            # Tải cơ sở dữ liệu OUI nếu chưa có
            download_oui_database() #tải cơ sở dữ liệu OUI nếu chưa có
            
            # Sử dụng lớp LocalMacLookup để tra cứu từ file cục bộ
            if os.path.exists(OUI_DB_PATH): #nếu file oui.csv tồn tại thì khởi tạo LocalMacLookup
                self.mac_lookup = LocalMacLookup(OUI_DB_PATH) #khởi tạo LocalMacLookup với file cục bộ
                print(f"Đã tải cơ sở dữ liệu OUI cục bộ: {len(self.mac_lookup.oui_dict)} entries") #in ra số lượng entries
            else: #nếu file không tồn tại thì thử dùng MacLookup mặc định
                if MAC_LOOKUP_AVAILABLE: #nếu MAC_LOOKUP_AVAILABLE là True thì khởi tạo MacLookup mặc định
                    try:
                        self.mac_lookup = MacLookup() #khởi tạo MacLookup mặc định
                        print("Sử dụng MacLookup mặc định (cần Internet)") #in ra thông báo
                    except:
                        pass #nếu có lỗi thì pass
        except Exception as e: #nếu có lỗi thì in ra lỗi
            print(f"Lỗi khi khởi tạo MAC lookup: {e}") #in ra lỗi
            # Fallback: thử dùng MacLookup mặc định nếu có
            if MAC_LOOKUP_AVAILABLE: #nếu MAC_LOOKUP_AVAILABLE là True thì thử khởi tạo MacLookup mặc định
                try:
                    self.mac_lookup = MacLookup() #khởi tạo MacLookup mặc định
                except:
                    self.mac_lookup = None #đặt mac_lookup là None
            else: #nếu MAC_LOOKUP_AVAILABLE là False thì đặt mac_lookup là None
                self.mac_lookup = None #đặt mac_lookup là None
        
        # Disable verbose output for Scapy
        if SCAPY_AVAILABLE: #nếu SCAPY_AVAILABLE là True thì khởi tạo conf.verb
            conf.verb = 0 #khởi tạo conf.verb
    
    def get_network_interfaces(self) -> List[Dict]: #lấy danh sách giao diện mạng
        """Lấy danh sách giao diện mạng"""
        interfaces = [] #khởi tạo biến interfaces
        if not PSUTIL_AVAILABLE: #nếu PSUTIL_AVAILABLE là False thì return interfaces
            return interfaces #nếu PSUTIL_AVAILABLE là False thì return interfaces
        
        try:
            addrs = psutil.net_if_addrs() #lấy danh sách địa chỉ IP của giao diện mạng
            stats = psutil.net_if_stats() #lấy thông tin về giao diện mạng
            
            for interface_name, addrs_list in addrs.items(): #vòng lặp để lấy danh sách địa chỉ IP của giao diện mạng
                if interface_name not in stats: #nếu interface_name không có trong stats thì continue
                    continue #nếu interface_name không có trong stats thì continue
                
                stats_info = stats[interface_name] #lấy thông tin về giao diện mạng
                if not stats_info.isup: #nếu stats_info.isup là False thì continue
                    continue #nếu stats_info.isup là False thì continue
                
                for addr in addrs_list: #vòng lặp để lấy danh sách địa chỉ IP của giao diện mạng
                    if addr.family == socket.AF_INET:  #nếu addr.family là socket.AF_INET thì try
                        try:
                            ip = ipaddress.IPv4Address(addr.address) #lấy địa chỉ IP của giao diện mạng
                            netmask = addr.netmask #lấy subnet mask của giao diện mạng
                            if netmask: #nếu netmask không phải là None thì lấy network của giao diện mạng
                                network = ipaddress.IPv4Network(f"{addr.address}/{netmask}", strict=False) #lấy network của giao diện mạng
                                interfaces.append({ #thêm network vào biến interfaces
                                    'name': interface_name, #tên giao diện mạng
                                    'ip': str(ip), #địa chỉ IP của giao diện mạng
                                    'netmask': netmask, #subnet mask của giao diện mạng
                                    'network': str(network.network_address), #network của giao diện mạng
                                    'cidr': str(network) #CIDR của giao diện mạng
                                })
                        except:
                            pass #nếu có lỗi thì pass
        except Exception as e: #nếu có lỗi thì in ra lỗi
            print(f"Error getting network interfaces: {e}") #in ra lỗi
        
        return interfaces #trả về danh sách giao diện mạng
    
    def get_hostname(self, ip: str) -> Optional[str]: #lấy hostname từ IP bằng reverse DNS
        """Lấy hostname từ IP bằng reverse DNS"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip) #lấy hostname từ IP bằng reverse DNS
            return hostname #trả về hostname
        except:
            return None #trả về None
    
    def get_vendor(self, mac: str) -> Optional[str]: #lấy vendor từ MAC address
        """Lấy vendor từ MAC address"""
        if not self.mac_lookup: #nếu mac_lookup không phải là None thì trả về None
            return None #trả về None
        try:
            # Format MAC address (remove separators if needed)
            mac_clean = mac.replace(':', '').replace('-', '').upper() #lấy MAC address và chuyển thành uppercase
            if len(mac_clean) >= 6: #nếu độ dài của mac_clean lớn hơn 6 thì lấy vendor từ MAC address
                return self.mac_lookup.lookup(mac) #trả về vendor từ MAC address
        except:
            pass #nếu có lỗi thì pass
        return None #trả về None
    
    def arp_scan(self, network: str) -> List[Dict]: #quét mạng bằng ARP
        """Quét mạng bằng ARP"""
        if not SCAPY_AVAILABLE: #nếu SCAPY_AVAILABLE là False thì trả về danh sách rỗng
            return [] #trả về danh sách rỗng
        
        results = [] #khởi tạo biến results
        try:
            # Tạo ARP request packet
            arp_request = ARP(pdst=network) #tạo ARP request packet
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") #tạo broadcast packet
            arp_request_broadcast = broadcast / arp_request #tạo ARP request broadcast packet
            
            # Gửi và nhận packet
            answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0] #gửi và nhận packet
            
            for element in answered_list: #vòng lặp để lấy kết quả quét
                ip = element[1].psrc #lấy IP từ packet
                mac = element[1].hwsrc #lấy MAC từ packet
                hostname = self.get_hostname(ip) #lấy hostname từ IP
                vendor = self.get_vendor(mac) #lấy vendor từ MAC
                
                results.append({ #thêm kết quả quét vào biến results
                    'ip': ip, #IP
                    'mac': mac, #MAC
                    'hostname': hostname, #hostname
                    'status': 'Online', #trạng thái
                    'vendor': vendor, #vendor
                    'method': 'ARP', #phương thức
                    'last_seen': datetime.now().isoformat() #thời gian
                })
        except Exception as e: #nếu có lỗi thì in ra lỗi
            print(f"ARP scan error: {e}") #in ra lỗi
        
        return results
    
    def icmp_scan(self, ip_range: List[str]) -> List[Dict]: #quét mạng bằng ICMP (ping)
        """Quét mạng bằng ICMP (ping)"""
        if not SCAPY_AVAILABLE: #nếu SCAPY_AVAILABLE là False thì trả về danh sách rỗng
            return [] #trả về danh sách rỗng
        
        results = [] #khởi tạo biến results
        q = Queue() #khởi tạo biến q
        
        for ip in ip_range: #vòng lặp để thêm IP vào biến q
            q.put(ip) #thêm IP vào biến q
        
        def ping_host(): #hàm ping host
            while not q.empty() and self.scanning: #vòng lặp để ping host
                try:
                    ip = q.get_nowait() #lấy IP từ biến q
                    packet = IP(dst=ip) / ICMP() #tạo packet ICMP
                    response = srp(packet, timeout=self.timeout, verbose=False)[0] #gửi và nhận packet
                    
                    if response: #nếu có response thì lấy MAC và hostname
                        mac = None #khởi tạo biến mac
                        hostname = self.get_hostname(ip) #lấy hostname từ IP
                        vendor = None #khởi tạo biến vendor
                        
                        # Thử lấy MAC bằng ARP
                        try:
                            mac = getmacbyip(ip) #lấy MAC từ IP
                            if mac: #nếu có MAC thì lấy Vendor từ MAC
                                vendor = self.get_vendor(mac) #lấy Vendor từ MAC
                        except:
                            pass #nếu có lỗi thì pass
                        
                        with self.lock:
                            results.append({ #thêm kết quả quét vào biến results
                                'ip': ip, #IP
                                'mac': mac or 'Unknown', #MAC
                                'hostname': hostname, #hostname
                                'status': 'Online', #trạng thái
                                'vendor': vendor, #vendor
                                'method': 'ICMP', #phương thức
                                'last_seen': datetime.now().isoformat() #thời gian quét
                            })
                except: #nếu có lỗi thì pass
                    pass
                finally: #nếu không có lỗi thì task_done
                    q.task_done() #task_done
        
        threads_list = [] #khởi tạo biến threads_list
        for _ in range(min(self.threads, len(ip_range))): #vòng lặp để thêm số luồng vào biến threads_list
            t = threading.Thread(target=ping_host, daemon=True) #đặt t là biến số luồng và ping_host là hàm target
            t.start() #bắt đầu số luồng
            threads_list.append(t) #thêm số luồng vào biến threads_list
        
        for t in threads_list: #vòng lặp để join số luồng
            t.join() #join số luồng
        
        return results #trả về danh sách kết quả quét
    
    def tcp_scan(self, ip: str, ports: List[int]) -> List[int]: #quét cổng TCP trên một IP
        """Quét cổng TCP trên một IP"""
        open_ports = [] #khởi tạo biến open_ports
        
        for port in ports: #vòng lặp để quét cổng
            if not self.scanning: #nếu trạng thái quét là False thì break
                break #thoát khỏi vòng lặp
            
            try: #nếu không có lỗi thì try
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #tạo socket
                sock.settimeout(0.5) #set timeout là 0.5 giây
                result = sock.connect_ex((ip, port)) #kết nối tới IP và port
                if result == 0: #nếu kết nối thành công thì thêm port vào biến open_ports
                    open_ports.append(port) #thêm port vào biến open_ports
                sock.close() #đóng socket
            except: #nếu có lỗi thì pass
                pass #nếu có lỗi thì pass
        
        return open_ports #trả về danh sách cổng mở
    
    def nmap_scan(self, ip: str, ports: str = None, scan_os: bool = False, scan_service: bool = False) -> Dict: #quét chi tiết bằng Nmap
        """Quét chi tiết bằng Nmap"""
        if not NMAP_AVAILABLE: #nếu NMAP_AVAILABLE là False thì trả về danh sách rỗng
            return {} #trả về danh sách rỗng
        
        result = { #khởi tạo biến result
            'ports': [],
            'os': None, #hệ điều hành
            'services': {} #dịch vụ
        }
        
        try: #nếu không có lỗi thì try
            nm = nmap.PortScanner() #đặt nm là biến nmap
            scan_args = '' #khởi tạo biến scan_args
            
            if scan_service: #nếu scan_service là True thì thêm -sV vào biến scan_args
                scan_args += '-sV' #thêm -sV vào biến scan_args (scan_service: quét dịch vụ)
            if scan_os: #nếu scan_os là True thì thêm -O vào biến scan_args
                scan_args += ' -O' #thêm -O vào biến scan_args (scan_os: quét hệ điều hành)
            
            if ports: #nếu ports không phải là None thì thêm -p vào biến scan_args
                scan_args += f' -p {ports}' #thêm -p vào biến scan_args (ports: cổng)
            
            nm.scan(ip, arguments=scan_args, timeout=self.timeout * 1000) #quét IP với scan_args và timeout
            
            if ip in nm.all_hosts(): #nếu IP có trong nm.all_hosts() thì lấy thông tin host
                host_info = nm[ip] #lấy thông tin host từ nm
                
                # Lấy cổng mở
                if 'tcp' in host_info: #nếu 'tcp' có trong host_info thì lấy cổng mở
                    for port in host_info['tcp']: #vòng lặp để lấy cổng mở
                        port_info = host_info['tcp'][port] #lấy thông tin cổng từ host_info
                        if port_info['state'] == 'open': #nếu trạng thái cổng là open thì thêm cổng vào biến result
                            result['ports'].append(port) #thêm cổng vào biến result
                            if scan_service: #nếu scan_service là True thì thêm dịch vụ vào biến result
                                result['services'][port] = { #thêm dịch vụ vào biến result
                                    'name': port_info.get('name', 'unknown'), #tên dịch vụ
                                    'product': port_info.get('product', ''), #sản phẩm dịch vụ
                                    'version': port_info.get('version', '') #phiên bản dịch vụ
                                }
                # Lấy OS
                if scan_os and 'osmatch' in host_info: #nếu scan_os là True và 'osmatch' có trong host_info thì lấy OS
                    os_matches = host_info['osmatch'] #lấy OS từ host_info
                    if os_matches: #nếu os_matches không phải là None thì thêm OS vào biến result
                        result['os'] = os_matches[0].get('name', 'Unknown') #thêm OS vào biến result
        except Exception as e: #nếu có lỗi thì in ra lỗi
            print(f"Nmap scan error for {ip}: {e}") #in ra lỗi
        
        return result #trả về kết quả quét
    
    def scan_network(self, network: str, scan_type: str, ports: List[int] = None, #quét mạng chính
                     deep_scan: bool = False) -> List[Dict]: #quét mạng chính
        """Quét mạng chính"""
        self.scanning = True #trạng thái quét là True
        self.results = [] #khởi tạo biến results
        
        try: #nếu không có lỗi thì try
            # Tạo danh sách IP
            network_obj = ipaddress.IPv4Network(network, strict=False) #tạo danh sách IP
            ip_list = [str(ip) for ip in network_obj.hosts()] #tạo danh sách IP
            
            total = len(ip_list) #tính tổng số IP
            
            # Bước 1: Phát hiện host online
            hosts = [] #khởi tạo biến hosts
            
            if scan_type in ['ARP', 'Tổng hợp']: #nếu scan_type là 'ARP' hoặc 'Tổng hợp' thì quét ARP
                if not self.scanning: #nếu trạng thái quét là False thì return rỗng
                    return [] #return rỗng
                arp_results = self.arp_scan(network) #quét ARP
                hosts.extend(arp_results) #thêm kết quả quét ARP vào biến hosts
            
            if scan_type in ['ICMP', 'Tổng hợp']: #nếu scan_type là 'ICMP' hoặc 'Tổng hợp' thì quét ICMP    
                if not self.scanning: #nếu trạng thái quét là False thì return rỗng
                    return [] #return rỗng
                icmp_results = self.icmp_scan(ip_list) #quét ICMP
                # Merge với ARP results
                existing_ips = {h['ip'] for h in hosts} #tạo danh sách IP
                for h in icmp_results: #vòng lặp để thêm kết quả quét ICMP vào biến hosts
                    if h['ip'] not in existing_ips: #nếu IP không có trong existing_ips thì thêm kết quả quét ICMP vào biến hosts
                        hosts.append(h) #thêm kết quả quét ICMP vào biến hosts
            
            if scan_type == 'TCP': #nếu scan_type là 'TCP' thì quét TCP
                # TCP scan cần danh sách IP cụ thể
                for ip in ip_list: #vòng lặp để quét TCP
                    if not self.scanning: #nếu trạng thái quét là False thì break
                        break #thoát khỏi vòng lặp
                    open_ports = self.tcp_scan(ip, ports or [80, 443, 22, 21]) #quét TCP
                    if open_ports: #nếu có cổng mở thì lấy hostname và MAC
                        hostname = self.get_hostname(ip) #lấy hostname từ IP
                        mac = None #khởi tạo biến mac
                        try: #nếu không có lỗi thì try
                            if SCAPY_AVAILABLE: #nếu SCAPY_AVAILABLE là True thì lấy MAC từ IP
                                mac = getmacbyip(ip) #lấy MAC từ IP
                        except: #nếu có lỗi thì pass
                            pass #nếu có lỗi thì pass
                        
                        hosts.append({ #thêm kết quả quét TCP vào biến hosts
                            'ip': ip, #IP
                            'mac': mac or 'Unknown', #MAC
                            'hostname': hostname, #hostname
                            'status': 'Online', #trạng thái
                            'ports': open_ports, #cổng mở
                            'vendor': self.get_vendor(mac) if mac else None, #Nhà sản xuất
                            'method': 'TCP', #phương thức
                            'last_seen': datetime.now().isoformat() #thời gian quét
                        })
            
            # Bước 2: Quét cổng và dịch vụ cho các host tìm được
            for idx, host in enumerate(hosts): #vòng lặp để quét cổng và dịch vụ cho các host tìm được
                if not self.scanning: #nếu trạng thái quét là False thì break
                    break #thoát khỏi vòng lập
                
                ip = host['ip'] #lấy IP từ host
                
                # Quét cổng nếu có chỉ định
                if ports and deep_scan: #nếu ports và deep_scan không phải là None thì quét cổng và dịch vụ
                    nmap_result = self.nmap_scan( #quét cổng và dịch vụ với Nmap
                        ip, #IP
                        ports=','.join(map(str, ports)), #cổng
                        scan_os=deep_scan, #quét OS
                        scan_service=deep_scan #quét dịch vụ
                    )
                    
                    if nmap_result.get('ports'): #nếu có cổng thì thêm cổng vào biến host
                        host['ports'] = nmap_result['ports'] #thêm cổng vào biến host
                    if nmap_result.get('os'): #nếu có OS thì thêm OS vào biến host
                        host['os'] = nmap_result['os'] #thêm OS vào biến host
                    if nmap_result.get('services'): #nếu có dịch vụ thì thêm dịch vụ vào biến host
                        host['services'] = nmap_result['services'] #thêm dịch vụ vào biến host
                
                self.results.append(host) #thêm host vào biến results
            
            return self.results #trả về danh sách kết quả quét
        
        except Exception as e: #nếu có lỗi thì in ra lỗi
            print(f"Scan error: {e}") #in ra lỗi
            import traceback #import traceback
            traceback.print_exc() #in ra lỗi
            return [] #trả về danh sách rỗng
        finally: #nếu không có lỗi thì finally
            self.scanning = False #trạng thái quét là False
    
    def stop_scan(self): #dừng quét
        """Dừng quét"""
        self.scanning = False #trạng thái quét là False
    
    def is_mac_database_ready(self) -> bool:
        """Kiểm tra xem cơ sở dữ liệu MAC vendor đã sẵn sàng chưa"""
        if isinstance(self.mac_lookup, LocalMacLookup): #nếu mac_lookup là LocalMacLookup
            return len(self.mac_lookup.oui_dict) > 0 #trả về True nếu có dữ liệu
        elif self.mac_lookup is not None: #nếu mac_lookup không phải None
            return True #trả về True
        return False #trả về False
    
    def update_mac_database_manual(self) -> bool:
        """Cập nhật cơ sở dữ liệu MAC vendor từ IEEE (force update)"""
        try:
            # Tải lại file từ IEEE
            if download_oui_database(force_update=True): #tải lại file với force_update=True
                # Nếu đang sử dụng LocalMacLookup, reload lại
                if isinstance(self.mac_lookup, LocalMacLookup): #nếu mac_lookup là LocalMacLookup
                    self.mac_lookup.reload() #tải lại cơ sở dữ liệu
                    print(f"Đã cập nhật cơ sở dữ liệu OUI: {len(self.mac_lookup.oui_dict)} entries") #in ra số lượng entries
                else: #nếu không phải LocalMacLookup thì khởi tạo lại
                    # Khởi tạo lại với LocalMacLookup
                    if os.path.exists(OUI_DB_PATH): #nếu file tồn tại
                        self.mac_lookup = LocalMacLookup(OUI_DB_PATH) #khởi tạo LocalMacLookup
                        print(f"Đã tải cơ sở dữ liệu OUI cục bộ: {len(self.mac_lookup.oui_dict)} entries") #in ra số lượng entries
                return True #trả về True
            return False #trả về False
        except Exception as e: #nếu có lỗi thì in ra lỗi
            print(f"Lỗi khi cập nhật cơ sở dữ liệu MAC vendor: {e}") #in ra lỗi
            return False #trả về False

