"""
Tab 3 - Phân tích
Phân tích chi tiết kết quả quét
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from network_scanner import NetworkScanner #thêm network_scanner.py vào để thực hiện quét mạng (NetworkScanner)
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import json

class AnalysisTab: #tạo tab phân tích
    def __init__(self, parent, app): #khởi tạo ứng dụng
        self.parent = parent #cửa sổ chính
        self.app = app #ứng dụng chính
        self.scanner = None #trình quét
        self.current_ip = None #IP hiện tại
        
        self.setup_ui() #thiết lập giao diện
    
    def setup_ui(self): #thiết lập giao diện
        """Thiết lập giao diện"""
        # Frame chính
        main_frame = ttk.Frame(self.parent, padding=20) #tạo khung chính
        main_frame.pack(fill=tk.BOTH, expand=True) #đặt khung chính vào cửa sổ
        
        # Tiêu đề
        title_frame = ttk.Frame(main_frame) #tạo khung tiêu đề
        title_frame.pack(fill=tk.X, pady=(0, 15)) #đặt khung tiêu đề vào cửa sổ
        
        ttk.Label(title_frame, #tạo nhãn tiêu đề
                 text="Phân tích chi tiết", #text cho tiêu đề
                 font=('Segoe UI', 14, 'bold')).pack(side=tk.LEFT) #đặt tiêu đề vào khung
        
        # Nhập IP
        input_frame = ttk.Frame(title_frame) #tạo khung nhập IP
        input_frame.pack(side=tk.RIGHT) #đặt khung nhập IP vào cửa sổ
        
        ttk.Label(input_frame, text="IP:").pack(side=tk.LEFT, padx=5) #đặt nhãn IP vào khung
        self.ip_var = tk.StringVar() #tạo biến IP
        ip_entry = ttk.Entry(input_frame, textvariable=self.ip_var, width=20) #tạo trường nhập IP
        ip_entry.pack(side=tk.LEFT, padx=5) #đặt trường nhập IP vào khung
        
        analyze_btn = ttk.Button(input_frame, #tạo nút phân tích
                                text="🔬 Phân tích", #text cho nút phân tích
                                command=self.analyze_current_ip) #sự kiện khi nhấn nút phân tích
        analyze_btn.pack(side=tk.LEFT, padx=5) #đặt nút phân tích vào khung
        
        # Notebook cho các phần phân tích
        self.analysis_notebook = ttk.Notebook(main_frame) #tạo notebook cho các phần phân tích
        self.analysis_notebook.pack(fill=tk.BOTH, expand=True) #đặt notebook cho các phần phân tích vào cửa sổ
        
        # Tab: Thông tin chung
        info_frame = ttk.Frame(self.analysis_notebook, padding=10) #tạo khung thông tin chung
        self.analysis_notebook.add(info_frame, text="📋 Thông tin chung") #đặt khung thông tin chung vào notebook
        self.setup_info_tab(info_frame) #thiết lập tab thông tin chung
        
        # Tab: Cổng và dịch vụ
        ports_frame = ttk.Frame(self.analysis_notebook, padding=10) #tạo khung cổng và dịch vụ
        self.analysis_notebook.add(ports_frame, text="🔌 Cổng & Dịch vụ") #Đặt khung cổng và dịch vụ vào notebook
        self.setup_ports_tab(ports_frame) #thiết lập tab cổng và dịch vụ
        
        # Tab: Phát hiện Hệ điều hành
        os_frame = ttk.Frame(self.analysis_notebook, padding=10) #tạo khung phát hiện Hệ điều hành
        self.analysis_notebook.add(os_frame, text="💻 Hệ điều hành") #Đặt khung phát hiện Hệ điều hành vào notebook
        self.setup_os_tab(os_frame) #thiết lập tab phát hiện Hệ điều hành
        
        # Tab: Raw XML
        xml_frame = ttk.Frame(self.analysis_notebook, padding=10) #tạo khung Raw XML
        self.analysis_notebook.add(xml_frame, text="📄 XML Raw") #Đặt khung Raw XML vào notebook
        self.setup_xml_tab(xml_frame) #thiết lập tab Raw XML
        
        # Tab: Cảnh báo lỗ hổng
        vuln_frame = ttk.Frame(self.analysis_notebook, padding=10) #tạo khung cảnh báo lỗ hổng
        self.analysis_notebook.add(vuln_frame, text="⚠️ Cảnh báo lỗ hổng") #Đặt khung cảnh báo lỗ hổng vào notebook
        self.setup_vulnerability_tab(vuln_frame) #thiết lập tab cảnh báo lỗ hổng
    
    def setup_info_tab(self, parent): #thiết lập tab thông tin
        """Thiết lập tab thông tin"""
        self.info_text = scrolledtext.ScrolledText(parent, #tạo trường nhập thông tin
                                                   wrap=tk.WORD, #đặt wrap cho trường nhập thông tin
                                                   font=('Consolas', 10), #đặt font cho trường nhập thông tin
                                                   height=20) #đặt chiều cao cho trường nhập thông tin
        self.info_text.pack(fill=tk.BOTH, expand=True) #đặt trường nhập thông tin vào khung
    
    def setup_ports_tab(self, parent): #thiết lập tab cổng
        """Thiết lập tab cổng"""
        # Thanh công cụ
        toolbar = ttk.Frame(parent) #tạo khung thanh công cụ
        toolbar.pack(fill=tk.X, pady=(0, 10)) #đặt khung thanh công cụ vào khung
        
        ttk.Label(toolbar, text="Cổng cần quét:").pack(side=tk.LEFT, padx=5) #đặt nhãn cổng cần quét vào khung
        self.ports_input_var = tk.StringVar(value="0–65535") #tạo biến cổng cần quét
        ports_entry = ttk.Entry(toolbar, textvariable=self.ports_input_var, width=20) #tạo trường nhập cổng cần quét
        ports_entry.pack(side=tk.LEFT, padx=5) #đặt trường nhập cổng cần quét vào khung
        
        ttk.Button(toolbar,
                  text="Quét cổng", #text cho nút quét cổng
                  command=self.scan_ports).pack(side=tk.LEFT, padx=5) #đặt nút quét cổng vào khung
        
        # Bảng
        table_frame = ttk.Frame(parent) #tạo khung bảng
        table_frame.pack(fill=tk.BOTH, expand=True) #đặt khung bảng vào khung
        
        columns = ('Port', 'State', 'Service', 'Product', 'Version') #tạo cột cho bảng
        self.ports_tree = ttk.Treeview(table_frame, columns=columns, show='headings') #tạo bảng cổng
        
        for col in columns: #vòng lặp để tạo cột cho bảng
            self.ports_tree.heading(col, text=col) #đặt tiêu đề cho cột
            self.ports_tree.column(col, width=100, anchor=tk.W) #đặt chiều rộng cho cột
        
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.ports_tree.yview) #tạo thanh cuộn cho bảng
        self.ports_tree.config(yscrollcommand=scrollbar.set) #đặt thanh cuộn cho bảng
        
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True) #đặt bảng cổng vào khung
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y) #đặt thanh cuộn cho bảng vào khung
    
    def setup_os_tab(self, parent): #thiết lập tab OS
        """Thiết lập tab OS"""
        self.os_text = scrolledtext.ScrolledText(parent, #tạo trường nhập thông tin
                                                wrap=tk.WORD, #đặt wrap cho trường nhập thông tin
                                                font=('Consolas', 10), #đặt font cho trường nhập thông tin
                                                height=20) #đặt chiều cao cho trường nhập thông tin
        self.os_text.pack(fill=tk.BOTH, expand=True) #đặt trường nhập thông tin vào khung
    
    def setup_xml_tab(self, parent): #thiết lập tab XML
        """Thiết lập tab XML"""
        self.xml_text = scrolledtext.ScrolledText(parent, #tạo trường nhập thông tin
                                                  wrap=tk.WORD, #đặt wrap cho trường nhập thông tin
                                                  font=('Consolas', 9), #đặt font cho trường nhập thông tin
                                                  height=20) #đặt chiều cao cho trường nhập thông tin
        self.xml_text.pack(fill=tk.BOTH, expand=True) #đặt trường nhập thông tin vào khung
    
    def setup_vulnerability_tab(self, parent): #thiết lập tab cảnh báo lỗ hổng
        """Thiết lập tab cảnh báo lỗ hổng"""
        # Thanh công cụ
        toolbar = ttk.Frame(parent) #tạo khung thanh công cụ
        toolbar.pack(fill=tk.X, pady=(0, 10)) #đặt khung thanh công cụ vào khung
        
        ttk.Button(toolbar,
                  text="📋 Sao chép dữ liệu phân tích",
                  command=self.copy_vulnerability_data).pack(side=tk.LEFT, padx=5) #nút sao chép dữ liệu
        
        ttk.Button(toolbar,
                  text="🔄 Làm mới biểu đồ",
                  command=self.refresh_vulnerability_chart).pack(side=tk.LEFT, padx=5) #nút làm mới biểu đồ
        
        # Khung chứa biểu đồ và thông tin
        content_frame = ttk.Frame(parent) #tạo khung nội dung
        content_frame.pack(fill=tk.BOTH, expand=True) #đặt khung nội dung vào khung
        
        # Khung biểu đồ
        chart_frame = ttk.Frame(content_frame) #tạo khung biểu đồ
        chart_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 10)) #đặt khung biểu đồ vào khung
        
        # Tạo figure cho matplotlib
        self.vuln_figure = Figure(figsize=(8, 6), dpi=100) #tạo figure cho matplotlib
        self.vuln_canvas = FigureCanvasTkAgg(self.vuln_figure, chart_frame) #tạo canvas cho matplotlib
        self.vuln_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True) #đặt canvas vào khung
        
        # Khung thông tin chi tiết
        info_frame = ttk.LabelFrame(content_frame, text="Chi tiết cảnh báo", padding=10) #tạo khung thông tin chi tiết
        info_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT) #đặt khung thông tin chi tiết vào khung
        
        self.vuln_text = scrolledtext.ScrolledText(info_frame, #tạo trường nhập thông tin
                                                   wrap=tk.WORD, #đặt wrap cho trường nhập thông tin
                                                   font=('Consolas', 9), #đặt font cho trường nhập thông tin
                                                   height=20) #đặt chiều cao cho trường nhập thông tin
        self.vuln_text.pack(fill=tk.BOTH, expand=True) #đặt trường nhập thông tin vào khung
        
        # Lưu trữ dữ liệu phân tích
        self.vulnerability_data = {} #dữ liệu phân tích lỗ hổng
    
    def analyze_ip(self, ip: str): #phân tích một IP
        """Phân tích một IP"""
        self.ip_var.set(ip) #đặt IP vào biến IP
        self.analyze_current_ip() #phân tích IP hiện tại
    
    def analyze_current_ip(self): #phân tích IP hiện tại
        """Phân tích IP hiện tại"""
        ip = self.ip_var.get().strip() #lấy IP từ biến IP
        if not ip: #nếu IP không hợp lệ thì return
            return
        
        self.current_ip = ip #đặt IP vào biến IP hiện tại
        
        # Tải trình quét
        if not self.scanner: #nếu trình quét không tồn tại thì tạo trình quét
            if self.app.settings_tab: #nếu tab cài đặt tồn tại thì lấy timeout và số luồng từ tab cài đặt
                timeout = self.app.settings_tab.get_timeout() #lấy timeout từ tab cài đặt
                threads = self.app.settings_tab.get_threads() #lấy số luồng từ tab cài đặt
                self.scanner = NetworkScanner(timeout=timeout, threads=threads) #tạo trình quét
            else: #nếu tab cài đặt không tồn tại thì tạo trình quét
                self.scanner = NetworkScanner() #tạo trình quét
        
        # Xóa dữ liệu trước đó
        self.info_text.delete(1.0, tk.END) #xóa dữ liệu trong trường nhập thông tin
        self.os_text.delete(1.0, tk.END) #xóa dữ liệu trong trường nhập thông tin OS
        self.xml_text.delete(1.0, tk.END) #xóa dữ liệu trong trường nhập thông tin XML
        self.vuln_text.delete(1.0, tk.END) #xóa dữ liệu trong trường nhập thông tin lỗ hổng
        for item in self.ports_tree.get_children(): #vòng lặp để xóa dữ liệu trong bảng cổng
            self.ports_tree.delete(item) #xóa dữ liệu trong bảng cổng
        
        # Hiển thị thông tin cơ bản
        self.info_text.insert(tk.END, f"Đang phân tích {ip}...\n\n") #hiển thị thông tin cơ bản
        
        # Bắt đầu phân tích trong thread
        threading.Thread(target=self._analyze_thread, args=(ip,), daemon=True).start() #bắt đầu phân tích trong thread
    
    def _analyze_thread(self, ip: str): #thread phân tích
        """Thread phân tích"""
        try: #nếu có lỗi thì in ra lỗi
            # Thông tin cơ bản
            hostname = self.scanner.get_hostname(ip) #lấy hostname từ IP
            mac = None #khởi tạo biến MAC
            vendor = None #khởi tạo biến Vendor
            
            try:
                from scapy.layers.l2 import getmacbyip #thêm scapy.layers.l2.getmacbyip vào để lấy MAC từ IP
                mac = getmacbyip(ip) #lấy MAC từ IP
                if mac: #nếu có MAC thì lấy Vendor từ MAC
                    vendor = self.scanner.get_vendor(mac) #lấy Vendor từ MAC
            except: #nếu có lỗi thì pass
                pass
            
            info_text = f"IP: {ip}\n" #hiển thị IP
            info_text += f"Hostname: {hostname or 'N/A'}\n" #hiển thị Hostname
            info_text += f"MAC: {mac or 'N/A'}\n" #hiển thị MAC
            info_text += f"Vendor: {vendor or 'N/A'}\n" #hiển thị Vendor
            info_text += f"\n{'='*50}\n\n" #hiển thị dòng ngăn cách
            
            self.parent.after(0, self._update_info, info_text) #cập nhật thông tin vào trường nhập thông tin
            
            # Quét sâu với Nmap
            nmap_result = self.scanner.nmap_scan( #quét cổng với Nmap
                ip, #IP cần quét
                ports=None, #cổng cần quét
                scan_os=True, #quét OS
                scan_service=True #quét dịch vụ
            ) #quét cổng
            
            # Cập nhật cổng
            if nmap_result.get('ports'): #nếu có cổng thì cập nhật cổng
                ports_data = [] #khởi tạo biến cổng
                for port in nmap_result['ports']: #vòng lặp để lấy cổng
                    service_info = nmap_result.get('services', {}).get(port, {}) #lấy dịch vụ từ cổng
                    ports_data.append(( #thêm cổng vào biến cổng
                        port,
                        'open', #trạng thái cổng
                        service_info.get('name', 'unknown'), #tên dịch vụ
                        service_info.get('product', ''), #sản phẩm dịch vụ
                        service_info.get('version', '') #phiên bản dịch vụ
                    )) #thêm cổng vào biến cổng
                
                self.parent.after(0, self._update_ports, ports_data) #cập nhật cổng vào bảng
                
                # Phân tích lỗ hổng và cập nhật biểu đồ
                self.parent.after(0, self._analyze_vulnerabilities, nmap_result, ip, hostname) #phân tích lỗ hổng
            
            # Cập nhật Hệ điều hành
            if nmap_result.get('os'): #nếu có Hệ điều hành thì cập nhật Hệ điều hành
                os_text = f"Hệ điều hành phát hiện:\n\n" #hiển thị Hệ điều hành
                os_text += f"{nmap_result['os']}\n" #hiển thị Hệ điều hành
                self.parent.after(0, self._update_os, os_text) #cập nhật Hệ điều hành vào trường nhập thông tin OS
            
            # Cập nhật thông tin với kết quả đầy đủ
            full_info = info_text #hiển thị thông tin cơ bản
            full_info += f"Cổng mở: {len(nmap_result.get('ports', []))}\n" #hiển thị số lượng cổng mở
            full_info += f"Hệ điều hành: {nmap_result.get('os', 'N/A')}\n" #hiển thị Hệ điều hành
            
            if nmap_result.get('services'): #nếu có dịch vụ thì cập nhật dịch vụ
                full_info += f"\nDịch vụ:\n" #hiển thị dịch vụ
                for port, info in nmap_result['services'].items(): #vòng lặp để lấy dịch vụ
                    full_info += f"  Port {port}: {info.get('name', 'unknown')}" #hiển thị tên dịch vụ
                    if info.get('product'): #nếu có sản phẩm dịch vụ thì hiển thị sản phẩm dịch vụ
                        full_info += f" - {info.get('product')}" #hiển thị sản phẩm dịch vụ
                    if info.get('version'): #nếu có phiên bản dịch vụ thì hiển thị phiên bản dịch vụ
                        full_info += f" {info.get('version')}" #hiển thị phiên bản dịch vụ
                    full_info += "\n" #hiển thị dòng ngăn cách
            
            self.parent.after(0, self._update_info, full_info) #cập nhật thông tin vào trường nhập thông tin
        
        except Exception as e: #nếu có lỗi thì in ra lỗi
            error_msg = f"Lỗi khi phân tích: {str(e)}\n" #hiển thị lỗi
            self.parent.after(0, self._update_info, error_msg) #cập nhật lỗi vào trường nhập thông tin
    
    def _update_info(self, text: str): #cập nhật thông tin
        """Cập nhật thông tin"""
        self.info_text.delete(1.0, tk.END) #xóa dữ liệu trong trường nhập thông tin
        self.info_text.insert(1.0, text) #hiển thị thông tin vào trường nhập thông tin
    
    def _update_ports(self, ports_data: list): #cập nhật bảng cổng
        """Cập nhật bảng cổng"""
        for item in self.ports_tree.get_children(): #vòng lặp để xóa dữ liệu trong bảng cổng
            self.ports_tree.delete(item) #xóa dữ liệu trong bảng cổng
        
        for data in ports_data: #vòng lặp để thêm cổng vào bảng cổng
            self.ports_tree.insert('', tk.END, values=data) #thêm cổng vào bảng cổng
    
    def _update_os(self, text: str): #cập nhật thông tin OS
        """Cập nhật thông tin OS"""
        self.os_text.delete(1.0, tk.END) #xóa dữ liệu trong trường nhập thông tin OS
        self.os_text.insert(1.0, text) #hiển thị thông tin vào trường nhập thông tin OS
    
    def scan_ports(self): #quét cổng
        """Quét cổng"""
        if not self.current_ip: #nếu IP hiện tại không tồn tại thì lấy IP từ biến IP
            ip = self.ip_var.get().strip() #lấy IP từ biến IP
            if not ip: #nếu IP không hợp lệ thì return
                return
            self.current_ip = ip #đặt IP vào biến IP hiện tại
        
        ports_str = self.ports_input_var.get().strip() #lấy cổng từ biến cổng
        if not ports_str: #nếu cổng không hợp lệ thì return
            return
        
        # Phân tích cổng
        ports = [] #khởi tạo biến cổng
        try:
            if '-' in ports_str: #nếu cổng có dấu '-' thì lấy cổng từ biến cổng
                start, end = map(int, ports_str.split('-')) #lấy cổng từ biến cổng
                ports = list(range(start, end + 1)) #lấy cổng từ biến cổng
            else: #nếu cổng không có dấu '-' thì lấy cổng từ biến cổng
                ports = [int(p.strip()) for p in ports_str.split(',')] #lấy cổng từ biến cổng
        except: #nếu có lỗi thì pass
            pass
        
        if not ports: #nếu cổng không hợp lệ thì return
            return
        
        # Xóa bảng
        for item in self.ports_tree.get_children(): #vòng lặp để xóa dữ liệu trong bảng cổng
            self.ports_tree.delete(item) #xóa dữ liệu trong bảng cổng
        
        # Quét
        if not self.scanner: #nếu trình quét không tồn tại thì tạo trình quét
            if self.app.settings_tab: #nếu tab cài đặt tồn tại thì lấy timeout và số luồng từ tab cài đặt
                timeout = self.app.settings_tab.get_timeout() #lấy timeout từ tab cài đặt
                threads = self.app.settings_tab.get_threads() #lấy số luồng từ tab cài đặt
                self.scanner = NetworkScanner(timeout=timeout, threads=threads) #tạo trình quét
            else: #nếu tab cài đặt không tồn tại thì tạo trình quét
                self.scanner = NetworkScanner() #tạo trình quét
        
        threading.Thread(target=self._scan_ports_thread, args=(self.current_ip, ports), daemon=True).start() #bắt đầu quét cổng trong thread
    
    def _scan_ports_thread(self, ip: str, ports: list): #thread quét cổng
        """Thread quét cổng"""
        try: #nếu có lỗi thì in ra lỗi
            ports_str = ','.join(map(str, ports)) #lấy cổng từ biến cổng
            nmap_result = self.scanner.nmap_scan( #quét cổng với Nmap
                ip,
                ports=ports_str, #cổng cần quét
                scan_os=False, #quét hệ điều hành
                scan_service=True #quét dịch vụ
            )
            
            ports_data = [] #khởi tạo biến cổng
            for port in nmap_result.get('ports', []): #vòng lặp để lấy cổng
                service_info = nmap_result.get('services', {}).get(port, {}) #lấy dịch vụ từ cổng
                ports_data.append(( #thêm cổng vào biến cổng
                    port,
                    'open', #trạng thái cổng
                    service_info.get('name', 'unknown'), #tên dịch vụ
                    service_info.get('product', ''), #sản phẩm dịch vụ
                    service_info.get('version', '') #phiên bản dịch vụ
                ))
            
            self.parent.after(0, self._update_ports, ports_data) #cập nhật cổng vào bảng
            
            # Phân tích lỗ hổng và cập nhật biểu đồ
            self.parent.after(0, self._analyze_vulnerabilities, nmap_result, ip, None) #phân tích lỗ hổng
        except Exception as e: #nếu có lỗi thì in ra lỗi
            pass #nếu có lỗi thì pass
    
    def refresh_data(self): #làm mới dữ liệu
        """Làm mới dữ liệu"""
        if self.current_ip: #nếu IP hiện tại tồn tại thì phân tích IP hiện tại
            self.analyze_current_ip() #phân tích IP hiện tại
    
    def _analyze_vulnerabilities(self, nmap_result: dict, ip: str, hostname: str = None): #phân tích lỗ hổng
        """Phân tích lỗ hổng dựa trên cổng mở"""
        # Cơ sở dữ liệu cổng nguy hiểm và lỗ hổng phổ biến
        vulnerable_ports = {
            21: {'risk': 'Cao', 'name': 'FTP', 'description': 'FTP không mã hóa, dễ bị đánh cắp thông tin đăng nhập'},
            22: {'risk': 'Trung bình', 'name': 'SSH', 'description': 'SSH có thể bị brute force nếu mật khẩu yếu'},
            23: {'risk': 'Cao', 'name': 'Telnet', 'description': 'Telnet không mã hóa, rất nguy hiểm'},
            25: {'risk': 'Trung bình', 'name': 'SMTP', 'description': 'SMTP có thể bị lạm dụng để gửi spam'},
            53: {'risk': 'Thấp', 'name': 'DNS', 'description': 'DNS có thể bị khai thác cho DNS tunneling'},
            80: {'risk': 'Trung bình', 'name': 'HTTP', 'description': 'HTTP không mã hóa, dữ liệu có thể bị đánh cắp'},
            110: {'risk': 'Trung bình', 'name': 'POP3', 'description': 'POP3 không mã hóa, email có thể bị đánh cắp'},
            135: {'risk': 'Cao', 'name': 'MSRPC', 'description': 'MSRPC có nhiều lỗ hổng đã biết'},
            139: {'risk': 'Cao', 'name': 'NetBIOS', 'description': 'NetBIOS có thể tiết lộ thông tin hệ thống'},
            143: {'risk': 'Trung bình', 'name': 'IMAP', 'description': 'IMAP không mã hóa, email có thể bị đánh cắp'},
            443: {'risk': 'Thấp', 'name': 'HTTPS', 'description': 'HTTPS an toàn nhưng cần kiểm tra chứng chỉ'},
            445: {'risk': 'Cao', 'name': 'SMB', 'description': 'SMB có nhiều lỗ hổng nghiêm trọng (EternalBlue, etc.)'},
            1433: {'risk': 'Cao', 'name': 'MSSQL', 'description': 'SQL Server có thể bị tấn công brute force'},
            3306: {'risk': 'Cao', 'name': 'MySQL', 'description': 'MySQL có thể bị tấn công nếu không được bảo mật'},
            3389: {'risk': 'Cao', 'name': 'RDP', 'description': 'RDP dễ bị brute force và khai thác lỗ hổng'},
            5432: {'risk': 'Cao', 'name': 'PostgreSQL', 'description': 'PostgreSQL có thể bị tấn công nếu không được bảo mật'},
            5900: {'risk': 'Cao', 'name': 'VNC', 'description': 'VNC không mã hóa, dễ bị đánh cắp mật khẩu'},
            8080: {'risk': 'Trung bình', 'name': 'HTTP-Proxy', 'description': 'HTTP Proxy có thể bị lạm dụng'},
            8443: {'risk': 'Thấp', 'name': 'HTTPS-Alt', 'description': 'HTTPS thay thế, cần kiểm tra cấu hình'},
        }
        
        ports = nmap_result.get('ports', []) #lấy danh sách cổng
        services = nmap_result.get('services', {}) #lấy thông tin dịch vụ
        
        # Phân loại cổng theo mức độ rủi ro
        high_risk = [] #cổng rủi ro cao
        medium_risk = [] #cổng rủi ro trung bình
        low_risk = [] #cổng rủi ro thấp
        unknown_risk = [] #cổng không xác định
        
        vulnerability_details = [] #chi tiết lỗ hổng
        
        for port in ports: #vòng lặp qua các cổng
            service_info = services.get(port, {}) #lấy thông tin dịch vụ
            service_name = service_info.get('name', 'unknown') #tên dịch vụ
            product = service_info.get('product', '') #sản phẩm
            version = service_info.get('version', '') #phiên bản
            
            if port in vulnerable_ports: #nếu cổng có trong danh sách cổng nguy hiểm
                vuln_info = vulnerable_ports[port] #lấy thông tin lỗ hổng
                risk_level = vuln_info['risk'] #mức độ rủi ro
                
                detail = {
                    'port': port,
                    'service': service_name,
                    'product': product,
                    'version': version,
                    'risk': risk_level,
                    'description': vuln_info['description']
                } #thông tin chi tiết
                
                vulnerability_details.append(detail) #thêm vào danh sách chi tiết
                
                if risk_level == 'Cao': #nếu rủi ro cao
                    high_risk.append(port) #thêm vào danh sách rủi ro cao
                elif risk_level == 'Trung bình': #nếu rủi ro trung bình
                    medium_risk.append(port) #thêm vào danh sách rủi ro trung bình
                else: #nếu rủi ro thấp
                    low_risk.append(port) #thêm vào danh sách rủi ro thấp
            else: #nếu cổng không có trong danh sách
                unknown_risk.append(port) #thêm vào danh sách không xác định
                vulnerability_details.append({
                    'port': port,
                    'service': service_name,
                    'product': product,
                    'version': version,
                    'risk': 'Không xác định',
                    'description': f'Cổng {port} mở nhưng chưa được phân loại rủi ro'
                }) #thông tin chi tiết
        
        # Lưu trữ dữ liệu phân tích
        self.vulnerability_data = {
            'ip': ip,
            'hostname': hostname,
            'total_ports': len(ports),
            'high_risk_count': len(high_risk),
            'medium_risk_count': len(medium_risk),
            'low_risk_count': len(low_risk),
            'unknown_risk_count': len(unknown_risk),
            'high_risk_ports': high_risk,
            'medium_risk_ports': medium_risk,
            'low_risk_ports': low_risk,
            'unknown_risk_ports': unknown_risk,
            'details': vulnerability_details,
            'timestamp': nmap_result.get('timestamp', '')
        } #dữ liệu phân tích
        
        # Vẽ biểu đồ
        self._draw_vulnerability_chart() #vẽ biểu đồ
        
        # Cập nhật thông tin chi tiết
        self._update_vulnerability_text() #cập nhật thông tin chi tiết
    
    def _draw_vulnerability_chart(self): #vẽ biểu đồ lỗ hổng
        """Vẽ biểu đồ cảnh báo lỗ hổng"""
        self.vuln_figure.clear() #xóa biểu đồ cũ
        
        if not self.vulnerability_data: #nếu không có dữ liệu
            ax = self.vuln_figure.add_subplot(111) #tạo subplot
            ax.text(0.5, 0.5, 'Chưa có dữ liệu phân tích.\nVui lòng quét cổng trước.', #thông báo
                   ha='center', va='center', fontsize=12, #căn giữa
                   transform=ax.transAxes) #transform
            self.vuln_canvas.draw() #vẽ biểu đồ
            return #trả về
        
        # Tạo biểu đồ cột
        ax = self.vuln_figure.add_subplot(111) #tạo subplot
        
        categories = ['Rủi ro Cao', 'Rủi ro Trung bình', 'Rủi ro Thấp', 'Không xác định'] #danh mục
        counts = [
            self.vulnerability_data['high_risk_count'],
            self.vulnerability_data['medium_risk_count'],
            self.vulnerability_data['low_risk_count'],
            self.vulnerability_data['unknown_risk_count']
        ] #số lượng
        
        colors = ['#dc3545', '#ffc107', '#28a745', '#6c757d'] #màu sắc
        
        bars = ax.bar(categories, counts, color=colors, alpha=0.7, edgecolor='black', linewidth=1.5) #vẽ cột
        
        # Thêm nhãn số trên mỗi cột
        for i, (bar, count) in enumerate(zip(bars, counts)): #vòng lặp
            if count > 0: #nếu có số lượng
                height = bar.get_height() #chiều cao
                ax.text(bar.get_x() + bar.get_width()/2., height, #vị trí
                       f'{count}', #số lượng
                       ha='center', va='bottom', fontsize=11, fontweight='bold') #căn giữa
        
        ax.set_ylabel('Số lượng cổng', fontsize=11, fontweight='bold') #nhãn trục Y
        ax.set_title(f'Phân tích lỗ hổng - {self.vulnerability_data.get("ip", "N/A")}', #tiêu đề
                    fontsize=12, fontweight='bold', pad=15) #font
        ax.set_ylim(0, max(counts) * 1.2 if max(counts) > 0 else 1) #giới hạn trục Y
        ax.grid(axis='y', alpha=0.3, linestyle='--') #lưới
        
        self.vuln_figure.tight_layout() #điều chỉnh layout
        self.vuln_canvas.draw() #vẽ biểu đồ
    
    def _update_vulnerability_text(self): #cập nhật thông tin lỗ hổng
        """Cập nhật thông tin chi tiết lỗ hổng"""
        if not self.vulnerability_data: #nếu không có dữ liệu
            self.vuln_text.delete(1.0, tk.END) #xóa dữ liệu
            self.vuln_text.insert(1.0, "Chưa có dữ liệu phân tích.") #thông báo
            return #trả về
        
        text = f"═══════════════════════════════════════════════════════\n" #dòng phân cách
        text += f"PHÂN TÍCH LỖ HỔNG BẢO MẬT\n" #tiêu đề
        text += f"═══════════════════════════════════════════════════════\n\n" #dòng phân cách
        
        text += f"IP: {self.vulnerability_data['ip']}\n" #IP
        if self.vulnerability_data.get('hostname'): #nếu có hostname
            text += f"Hostname: {self.vulnerability_data['hostname']}\n" #hostname
        text += f"Tổng số cổng mở: {self.vulnerability_data['total_ports']}\n\n" #tổng số cổng
        
        text += f"📊 THỐNG KÊ RỦI RO:\n" #thống kê
        text += f"  ⚠️  Rủi ro Cao: {self.vulnerability_data['high_risk_count']} cổng\n" #rủi ro cao
        text += f"  ⚡ Rủi ro Trung bình: {self.vulnerability_data['medium_risk_count']} cổng\n" #rủi ro trung bình
        text += f"  ✓  Rủi ro Thấp: {self.vulnerability_data['low_risk_count']} cổng\n" #rủi ro thấp
        text += f"  ❓ Không xác định: {self.vulnerability_data['unknown_risk_count']} cổng\n\n" #không xác định
        
        if self.vulnerability_data['high_risk_count'] > 0: #nếu có rủi ro cao
            text += f"🚨 CỔNG RỦI RO CAO:\n" #cổng rủi ro cao
            for port in self.vulnerability_data['high_risk_ports']: #vòng lặp
                detail = next((d for d in self.vulnerability_data['details'] if d['port'] == port), None) #tìm chi tiết
                if detail: #nếu có chi tiết
                    text += f"  • Port {port} ({detail['service']})" #cổng
                    if detail.get('product'): #nếu có sản phẩm
                        text += f" - {detail['product']}" #sản phẩm
                    if detail.get('version'): #nếu có phiên bản
                        text += f" {detail['version']}" #phiên bản
                    text += f"\n    → {detail['description']}\n" #mô tả
            text += "\n" #dòng trống
        
        if self.vulnerability_data['medium_risk_count'] > 0: #nếu có rủi ro trung bình
            text += f"⚡ CỔNG RỦI RO TRUNG BÌNH:\n" #cổng rủi ro trung bình
            for port in self.vulnerability_data['medium_risk_ports']: #vòng lặp
                detail = next((d for d in self.vulnerability_data['details'] if d['port'] == port), None) #tìm chi tiết
                if detail: #nếu có chi tiết
                    text += f"  • Port {port} ({detail['service']})" #cổng
                    if detail.get('product'): #nếu có sản phẩm
                        text += f" - {detail['product']}" #sản phẩm
                    if detail.get('version'): #nếu có phiên bản
                        text += f" {detail['version']}" #phiên bản
                    text += f"\n    → {detail['description']}\n" #mô tả
            text += "\n" #dòng trống
        
        text += f"═══════════════════════════════════════════════════════\n" #dòng phân cách
        text += f"💡 KHUYẾN NGHỊ:\n" #khuyến nghị
        text += f"  • Đóng các cổng không cần thiết\n" #khuyến nghị
        text += f"  • Sử dụng firewall để kiểm soát truy cập\n" #khuyến nghị
        text += f"  • Cập nhật phần mềm và dịch vụ thường xuyên\n" #khuyến nghị
        text += f"  • Sử dụng mật khẩu mạnh và xác thực đa yếu tố\n" #khuyến nghị
        text += f"  • Mã hóa các dịch vụ không an toàn (FTP, Telnet)\n" #khuyến nghị
        
        self.vuln_text.delete(1.0, tk.END) #xóa dữ liệu
        self.vuln_text.insert(1.0, text) #chèn văn bản
    
    def copy_vulnerability_data(self): #sao chép dữ liệu lỗ hổng
        """Sao chép dữ liệu phân tích để gửi cho AI"""
        if not self.vulnerability_data: #nếu không có dữ liệu
            messagebox.showwarning("Cảnh báo", "Chưa có dữ liệu phân tích để sao chép.") #thông báo
            return #trả về
        
        # Tạo JSON format để dễ đọc và phân tích
        data_to_copy = {
            'target': {
                'ip': self.vulnerability_data['ip'],
                'hostname': self.vulnerability_data.get('hostname', 'N/A')
            },
            'summary': {
                'total_open_ports': self.vulnerability_data['total_ports'],
                'high_risk_ports': self.vulnerability_data['high_risk_count'],
                'medium_risk_ports': self.vulnerability_data['medium_risk_count'],
                'low_risk_ports': self.vulnerability_data['low_risk_count'],
                'unknown_risk_ports': self.vulnerability_data['unknown_risk_count']
            },
            'ports': []
        } #dữ liệu để sao chép
        
        for detail in self.vulnerability_data['details']: #vòng lặp
            port_info = {
                'port': detail['port'],
                'service': detail['service'],
                'product': detail.get('product', ''),
                'version': detail.get('version', ''),
                'risk_level': detail['risk'],
                'vulnerability_description': detail['description']
            } #thông tin cổng
            data_to_copy['ports'].append(port_info) #thêm vào danh sách
        
        # Chuyển đổi sang JSON với định dạng đẹp
        json_data = json.dumps(data_to_copy, indent=2, ensure_ascii=False) #chuyển đổi sang JSON
        
        # Sao chép vào clipboard
        self.parent.clipboard_clear() #xóa clipboard
        self.parent.clipboard_append(json_data) #thêm vào clipboard
        
        messagebox.showinfo("Thành công", 
                          "Đã sao chép dữ liệu phân tích vào clipboard!\n\n"
                          "Bạn có thể dán (Ctrl+V) vào AI để phân tích sâu hơn.") #thông báo
    
    def refresh_vulnerability_chart(self): #làm mới biểu đồ lỗ hổng
        """Làm mới biểu đồ lỗ hổng"""
        if self.vulnerability_data: #nếu có dữ liệu
            self._draw_vulnerability_chart() #vẽ lại biểu đồ
            self._update_vulnerability_text() #cập nhật lại thông tin
        else: #nếu không có dữ liệu
            messagebox.showinfo("Thông tin", "Chưa có dữ liệu phân tích. Vui lòng quét cổng trước.") #thông báo

