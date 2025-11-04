"""
Tab 2 - Kết quả
Hiển thị và quản lý kết quả quét
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import csv
from datetime import datetime

class ResultsTab: #tạo tab kết quả
    def __init__(self, parent, app): #khởi tạo ứng dụng
        self.parent = parent #cửa sổ chính
        self.app = app #ứng dụng chính
        self.results = [] #khởi tạo biến results
        
        self.setup_ui() #gọi hàm thiết lập giao diện
    
    def setup_ui(self): #thiết lập giao diện
        """Thiết lập giao diện"""
        # Khung chính
        main_frame = ttk.Frame(self.parent, padding=10) #tạo khung chính
        main_frame.pack(fill=tk.BOTH, expand=True) #đặt khung chính vào cửa sổ
        
        # Thanh công cụ
        toolbar_frame = ttk.Frame(main_frame) #tạo khung thanh công cụ
        toolbar_frame.pack(fill=tk.X, pady=(0, 10)) #đặt khung thanh công cụ vào cửa sổ
        
        # Tìm kiếm và lọc
        search_frame = ttk.Frame(toolbar_frame) #tạo khung tìm kiếm và lọc
        search_frame.pack(side=tk.LEFT, fill=tk.X, expand=True) #đặt khung tìm kiếm và lọc vào cửa sổ
        
        ttk.Label(search_frame, text="🔍 Tìm kiếm:").pack(side=tk.LEFT, padx=5) #đặt nhãn tìm kiếm vào khung
        self.search_var = tk.StringVar() #tạo biến tìm kiếm
        self.search_var.trace('w', self.on_search) #gọi hàm tìm kiếm
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30) #tạo trường nhập tìm kiếm
        search_entry.pack(side=tk.LEFT, padx=5) #đặt trường nhập tìm kiếm vào cửa sổ
        
        # Lọc theo trạng thái
        ttk.Label(search_frame, text="Lọc:").pack(side=tk.LEFT, padx=(20, 5)) #đặt nhãn lọc vào khung
        self.filter_var = tk.StringVar(value="Tất cả") #tạo biến lọc
        filter_combo = ttk.Combobox(search_frame, #tạo combobox lọc
                                    textvariable=self.filter_var, #biến lọc
                                    values=["Tất cả", "Online", "Offline"], #giá trị lọc
                                    state="readonly", #trạng thái lọc
                                    width=10) #chiều rộng lọc
        filter_combo.pack(side=tk.LEFT, padx=5) #đặt combobox lọc vào cửa sổ
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_table()) #gọi hàm lọc
        
        # Nút
        button_frame = ttk.Frame(toolbar_frame) #tạo khung nút
        button_frame.pack(side=tk.RIGHT) #đặt khung nút vào cửa sổ
        
        ttk.Button(button_frame, #tạo nút xuất CSV
                  text="📥 Xuất CSV", #text cho nút xuất CSV
                  command=self.export_csv).pack(side=tk.LEFT, padx=2) #đặt nút xuất CSV vào cửa sổ
        
        ttk.Button(button_frame, #tạo nút xuất JSON
                  text="📥 Xuất JSON", #text cho nút xuất JSON
                  command=self.export_json).pack(side=tk.LEFT, padx=2) #đặt nút xuất JSON vào cửa sổ
        
        ttk.Button(button_frame, #tạo nút xóa kết quả
                  text="🗑️ Xóa kết quả", #text cho nút xóa kết quả
                  command=self.clear_results).pack(side=tk.LEFT, padx=2) #đặt nút xóa kết quả vào cửa sổ
        
        # Bảng kết quả
        table_frame = ttk.Frame(main_frame) #tạo khung bảng kết quả
        table_frame.pack(fill=tk.BOTH, expand=True) #đặt khung bảng kết quả vào cửa sổ
        
        # Treeview với thanh cuộn dọc và ngang
        scrollbar_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL) #tạo thanh cuộn dọc
        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL) #tạo thanh cuộn ngang
        
        columns = ('IP', 'Hostname', 'MAC', 'Status', 'Ports', 'OS', 'Service', 'Vendor', 'Last Seen') #tạo cột cho bảng
        self.tree = ttk.Treeview(table_frame, #tạo bảng kết quả
                                columns=columns, #cột cho bảng
                                show='headings', #hiển thị tiêu đề
                                yscrollcommand=scrollbar_y.set, #thanh cuộn dọc
                                xscrollcommand=scrollbar_x.set) #thanh cuộn ngang
        
        scrollbar_y.config(command=self.tree.yview) #đặt thanh cuộn dọc vào bảng
        scrollbar_x.config(command=self.tree.xview) #đặt thanh cuộn ngang vào bảng
        
        # Cấu hình cột
        column_widths = { #tạo chiều rộng cho cột
            'IP': 120, #chiều rộng cột IP
            'Hostname': 150, #chiều rộng cột Hostname
            'MAC': 130, #chiều rộng cột MAC
            'Status': 80, #chiều rộng cột Status
            'Ports': 150, #chiều rộng cột Ports
            'OS': 150, #chiều rộng cột OS
            'Service': 200, #chiều rộng cột Service
            'Vendor': 150, #chiều rộng cột Vendor
            'Last Seen': 150 #chiều rộng cột Last Seen
        }
        
        for col in columns: #vòng lặp để tạo tiêu đề cho cột
            self.tree.heading(col, text=col) #đặt tiêu đề cho cột
            self.tree.column(col, width=column_widths.get(col, 100), anchor=tk.W) #đặt chiều rộng cho cột
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True) #đặt bảng kết quả vào cửa sổ
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y) #đặt thanh cuộn dọc vào cửa sổ
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X) #đặt thanh cuộn ngang vào cửa sổ
        
        # Context menu
        self.context_menu = tk.Menu(self.parent, tearoff=0) #tạo menu ngữ cảnh
        self.context_menu.add_command(label="📋 Copy IP", command=self.copy_ip) #đặt lệnh copy IP vào menu ngữ cảnh
        self.context_menu.add_command(label="📋 Copy Hostname", command=self.copy_hostname) #đặt lệnh copy Hostname vào menu ngữ cảnh
        self.context_menu.add_command(label="📋 Copy Vendor", command=self.copy_vendor) #đặt lệnh copy Vendor vào menu ngữ cảnh
        self.context_menu.add_separator() #đặt dấu phân cách vào menu ngữ cảnh
        self.context_menu.add_command(label="🔬 Phân tích sâu", command=self.deep_analyze) #đặt lệnh phân tích sâu vào menu ngữ cảnh    
        self.context_menu.add_separator() #đặt dấu phân cách vào menu ngữ cảnh
        self.context_menu.add_command(label="🗑️ Xóa", command=self.delete_selected) #đặt lệnh xóa vào menu ngữ cảnh
        
        self.tree.bind("<Button-3>", self.show_context_menu) #gọi hàm show_context_menu khi click chuột phải
        self.tree.bind("<Double-Button-1>", self.on_double_click) #gọi hàm on_double_click khi double click
    
    def update_results(self, results: list): #cập nhật kết quả  
        """Cập nhật kết quả"""
        self.results = results #cập nhật kết quả
        self.refresh_table() #gọi hàm refresh_table
    
    def refresh_table(self): #làm mới bảng
        """Làm mới bảng"""
        # Xóa bảng
        for item in self.tree.get_children(): #vòng lặp để xóa dữ liệu trong bảng
            self.tree.delete(item) #xóa dữ liệu trong bảng
        
        # Lọc kết quả
        filtered = self.filter_results() #lọc kết quả
        
        # Thêm vào bảng
        for result in filtered: #vòng lặp để thêm kết quả vào bảng
            ip = result.get('ip', 'Unknown') #lấy IP
            hostname = result.get('hostname', 'N/A') #lấy Hostname
            mac = result.get('mac', 'Unknown') #lấy MAC
            status = result.get('status', 'Unknown') #lấy Status
            ports = result.get('ports', []) #lấy Ports
            os_info = result.get('os', 'N/A') #lấy OS
            services = result.get('services', {}) #lấy Services
            vendor = result.get('vendor', 'N/A') #lấy Vendor
            last_seen = result.get('last_seen', 'N/A') #lấy Last Seen
            
            # Định dạng Ports
            ports_str = ', '.join(map(str, ports)) if ports else 'N/A'
            
            # Định dạng Services
            if services:
                service_list = [] #khởi tạo biến service_list
                for port, info in services.items(): #vòng lặp để lấy Services
                    name = info.get('name', 'unknown') #lấy tên Services
                    product = info.get('product', '') #lấy sản phẩm Services
                    if product: #nếu sản phẩm Services không phải là None thì thêm sản phẩm Services vào biến service_list
                        service_list.append(f"{port}/{name} ({product})") #thêm sản phẩm Services vào biến service_list
                    else: #nếu sản phẩm Services là None thì thêm tên Services vào biến service_list
                        service_list.append(f"{port}/{name}") #thêm tên Services vào biến service_list
                service_str = ', '.join(service_list) #định dạng Services
            else: #nếu services là None thì định dạng Services là 'N/A'
                service_str = 'N/A' #định dạng Services là 'N/A'
            
            # Định dạng Last Seen
            if last_seen != 'N/A': #nếu Last Seen không phải là 'N/A' thì định dạng Last Seen
                try: #nếu có lỗi thì in ra lỗi
                    dt = datetime.fromisoformat(last_seen) #lấy Last Seen từ biến last_seen
                    last_seen = dt.strftime("%Y-%m-%d %H:%M:%S") #định dạng Last Seen
                except: #nếu có lỗi thì pass
                    pass
            
            self.tree.insert('', tk.END, values=( #thêm kết quả vào bảng
                ip, hostname, mac, status, ports_str, #IP, Hostname, MAC, Status, Ports
                os_info, service_str, vendor, last_seen #OS, Service, Vendor, Last Seen
            ), tags=(status.lower(),)) #đặt màu cho bảng
        
        # Tag màu
        self.tree.tag_configure('online', background='#d4edda') #đặt màu cho bảng online
        self.tree.tag_configure('offline', background='#f8d7da') #đặt màu cho bảng offline
    
    def filter_results(self) -> list: #lọc kết quả
        """Lọc kết quả"""
        filtered = self.results.copy() #lọc kết quả
        
        # Filter by status
        status_filter = self.filter_var.get() #lấy trạng thái lọc
        if status_filter != "Tất cả": #nếu trạng thái lọc không phải là 'Tất cả' thì lọc kết quả
            filtered = [r for r in filtered if r.get('status', '').lower() == status_filter.lower()] #lọc kết quả
        
        # Tìm kiếm lọc theo IP, Hostname, MAC, Vendor
        search_term = self.search_var.get().lower() #lấy từ khóa tìm kiếm
        if search_term: #nếu tìm kiếm không phải là None thì lọc kết quả
            filtered = [ #lọc kết quả
                r for r in filtered #vòng lặp để lọc kết quả
                if search_term in str(r.get('ip', '')).lower() or #nếu tìm kiếm không phải là None thì lọc kết quả
                   search_term in str(r.get('hostname', '')).lower() or #nếu tìm kiếm không phải là None thì lọc kết quả
                   search_term in str(r.get('mac', '')).lower() or #nếu tìm kiếm không phải là None thì lọc kết quả
                   search_term in str(r.get('vendor', '')).lower() #nếu tìm kiếm không phải là None thì lọc kết quả
            ]
        
        return filtered #trả về danh sách kết quả lọc
    
    def on_search(self, *args): #xử lý tìm kiếm
        """Xử lý tìm kiếm"""
        self.refresh_table() #gọi hàm refresh_table
    
    def show_context_menu(self, event): #hiển thị menu ngữ cảnh
        """Hiển thị menu ngữ cảnh"""
        item = self.tree.selection()[0] if self.tree.selection() else None #lấy item được chọn
        if item: #nếu item không phải là None thì hiển thị menu ngữ cảnh
            self.context_menu.post(event.x_root, event.y_root) #hiển thị menu ngữ cảnh
    
    def get_selected_item(self) -> dict: #lấy item được chọn
        """Lấy item được chọn"""
        selection = self.tree.selection() #lấy item được chọn
        if not selection: #nếu item được chọn là None thì trả về None
            return None
        
        item = selection[0] #lấy item được chọn
        values = self.tree.item(item, 'values') #lấy giá trị của item
        
        if not values: #nếu giá trị của item là None thì trả về None
            return None
        
        # Tìm kết quả tương ứng
        ip = values[0] #lấy IP của kết quả tương ứng
        for result in self.results: #vòng lặp để tìm kết quả tương ứng
            if result.get('ip') == ip: #nếu IP của kết quả tương ứng không phải là None thì trả về kết quả tương ứng
                return result #trả về kết quả tương ứng
        
        return None #trả về None
    
    def copy_ip(self): #copy IP
        """Copy IP"""
        result = self.get_selected_item() #lấy item được chọn
        if result: #nếu item không phải là None thì copy IP
            self.parent.clipboard_clear() #xóa clipboard
            self.parent.clipboard_append(result.get('ip', '')) #copy IP vào clipboard
            messagebox.showinfo("Thành công", "Đã copy IP vào clipboard") #hiển thị thông báo thành công
    
    def copy_hostname(self): #copy Hostname
        """Copy Hostname"""
        result = self.get_selected_item() #lấy item được chọn
        if result: #nếu item không phải là None thì copy Hostname
            hostname = result.get('hostname', 'N/A') #lấy Hostname từ item
            self.parent.clipboard_clear() #xóa clipboard
            self.parent.clipboard_append(hostname) #copy Hostname vào clipboard
            messagebox.showinfo("Thành công", "Đã copy Hostname vào clipboard") #hiển thị thông báo thành công
    
    def copy_vendor(self): #copy nhà sản xuất
        """Copy Vendor"""
        result = self.get_selected_item() #lấy item được chọn
        if result:
            vendor = result.get('vendor', 'N/A') #lấy nhà sản xuất từ item
            self.parent.clipboard_clear() #xóa clipboard
            self.parent.clipboard_append(vendor) #copy nhà sản xuất vào clipboard
            messagebox.showinfo("Thành công", "Đã copy Vendor vào clipboard") #hiển thị thông báo thành công
    
    def deep_analyze(self): #phân tích sâu
        """Phân tích sâu"""
        result = self.get_selected_item() # lấy item được chọn
        if not result: #nếu item được chọn là None thì trả về None
            return #trả về None
        
        ip = result.get('ip') #lấy IP từ item
        if not ip: #nếu IP là None thì trả về None
            return #trả về None
        
        # Chuyển sang tab phân tích
        self.app.notebook.select(2) #chuyển sang tab phân tích
        if self.app.analysis_tab: #nếu tab phân tích tồn tại thì phân tích IP
            self.app.analysis_tab.analyze_ip(ip) #phân tích IP
    
    def delete_selected(self): #xóa item được chọn
        """Xóa item được chọn"""
        result = self.get_selected_item() #lấy item được chọn
        if not result: #nếu item được chọn là None thì trả về None
            return #trả về None
        
        if messagebox.askyesno("Xác nhận", "Bạn có chắc muốn xóa thiết bị này?"): #hiển thị thông báo xác nhận
            ip = result.get('ip') #lấy IP từ item
            self.results = [r for r in self.results if r.get('ip') != ip] #xóa item được chọn
            self.refresh_table() #gọi hàm refresh_table
    
    def on_double_click(self, event): #xử lý double click
        """Xử lý double click"""
        self.deep_analyze() #gọi hàm deep_analyze
    
    def export_csv(self): #xuất ra CSV
        """Xuất ra CSV"""
        if not self.results: #nếu không có dữ liệu để xuất thì hiển thị thông báo cảnh báo
            messagebox.showwarning("Cảnh báo", "Không có dữ liệu để xuất!") #hiển thị thông báo cảnh báo
            return
        
        filename = filedialog.asksaveasfilename( #lấy tên file
            defaultextension=".csv", #định dạng file
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")] #định dạng file
        )
        
        if not filename: #nếu tên file là None thì trả về None
            return #trả về None
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f: #mở file
                writer = csv.writer(f) #tạo bản ghi
                writer.writerow(['IP', 'Hostname', 'MAC', 'Status', 'Ports', 'OS', 'Service', 'Vendor', 'Last Seen']) #thêm tiêu đề các cột vào file
                
                for result in self.results: #vòng lặp để lấy kết quả
                    ports = result.get('ports', []) #lấy cổng từ kết quả
                    ports_str = ', '.join(map(str, ports)) if ports else 'N/A' #định dạng cổng
                    
                    services = result.get('services', {}) #lấy dịch vụ từ kết quả
                    service_str = str(services) if services else 'N/A' #định dạng dịch vụ
                    
                    writer.writerow([ #thêm kết quả vào file
                        result.get('ip', ''), #lấy IP từ kết quả
                        result.get('hostname', 'N/A'), #lấy Hostname từ kết quả
                        result.get('mac', 'Unknown'), #lấy MAC từ kết quả
                        result.get('status', 'Unknown'), #lấy Status từ kết quả
                        ports_str, #định dạng cổng
                        result.get('os', 'N/A'), #lấy OS từ kết quả
                        service_str, #định dạng dịch vụ
                        result.get('vendor', 'N/A'), #lấy Vendor từ kết quả
                        result.get('last_seen', 'N/A') #lấy Last Seen từ kết quả
                    ])
            
            messagebox.showinfo("Thành công", f"Đã xuất ra {filename}") #hiển thị thông báo thành công
        except Exception as e: #nếu có lỗi thì in ra lỗi
            messagebox.showerror("Lỗi", f"Không thể xuất file:\n{e}") #hiển thị thông báo lỗi
    
    def export_json(self): #xuất ra JSON
        """Xuất ra JSON"""
        if not self.results: #nếu không có dữ liệu để xuất thì hiển thị thông báo cảnh báo
            messagebox.showwarning("Cảnh báo", "Không có dữ liệu để xuất!") #hiển thị thông báo cảnh báo
            return #trả về None
        
        filename = filedialog.asksaveasfilename( #lấy tên file
            defaultextension=".json", #định dạng file
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")] #định dạng file
        )
        
        if not filename: #nếu tên file là None thì trả về None
            return
        
        try:
            with open(filename, 'w', encoding='utf-8') as f: #mở file
                json.dump(self.results, f, indent=2, ensure_ascii=False) #xuất ra JSON
            
            messagebox.showinfo("Thành công", f"Đã xuất ra {filename}") #hiển thị thông báo thành công
        except Exception as e: #nếu có lỗi thì in ra lỗi
            messagebox.showerror("Lỗi", f"Không thể xuất file:\n{e}") #hiển thị thông báo lỗi
    
    def clear_results(self): #xóa tất cả kết quả
        """Xóa tất cả kết quả"""
        if not self.results: #nếu không có dữ liệu để xóa thì trả về None
            return #trả về None nếu không có dữ liệu để xóa
        
        if messagebox.askyesno("Xác nhận", "Bạn có chắc muốn xóa tất cả kết quả?"): #hiển thị thông báo xác nhận
            self.results = [] #xóa tất cả kết quả
            self.refresh_table() #gọi hàm refresh_table
            messagebox.showinfo("Thành công", "Đã xóa tất cả kết quả") #hiển thị thông báo thành công

