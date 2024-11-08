from scapy.all import sniff, conf, IP, TCP, UDP, Raw, ICMP, DNS
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
from datetime import datetime
import sqlite3
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
from matplotlib.figure import Figure
import ipaddress


class NetworkAnalyzer:
    def __init__(self):
        # Statistics dictionaries
        self.stats = {
            "total_packets": 0,
            "protocols": defaultdict(int),
            "ip_connections": defaultdict(int),
            "ports": defaultdict(int),
            "traffic_history": defaultdict(list),
            "packet_sizes": defaultdict(list),
        }

        # Filters
        self.ip_filters = {"source": set(), "destination": set()}
        self.protocol_filter = set()
        self.packet_size_filter = {"min": None, "max": None}

        # Graph update interval (ms)
        self.graph_update_interval = 1000

        # Thread-safe queue for database operations
        self.db_queue = queue.Queue()

        # Capture control flag
        self.capture_active = False

        # Create database connection in main thread
        self.create_database()

        # Start database worker thread
        self.db_thread = threading.Thread(target=self.database_worker)
        self.db_thread.daemon = True
        self.db_thread.start()

        # GUI initialization
        self.setup_gui()

        # Initialize graphs
        self.setup_graphs()

        # Start graph animation
        self.animate_graphs()

    def create_database(self):
        self.conn = sqlite3.connect("network_traffic.db")
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                payload TEXT,
                packet_size INTEGER
            )"""
        )
        self.conn.commit()

    def database_worker(self):
        """Worker thread for handling database operations"""
        db_conn = sqlite3.connect("network_traffic.db")
        cursor = db_conn.cursor()

        while True:
            try:
                operation = self.db_queue.get()
                if operation is None:  # Shutdown signal
                    break

                cursor.execute(
                    """
                    INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, payload, packet_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    operation,
                )
                db_conn.commit()

            except Exception as e:
                print(f"Database error: {e}")
            finally:
                self.db_queue.task_done()

        db_conn.close()

    def setup_graphs(self):
        """Initialize matplotlib figures for real-time graphs"""
        # Create figure for protocol distribution
        self.protocol_fig = Figure(figsize=(6, 4))
        self.protocol_ax = self.protocol_fig.add_subplot(111)
        self.protocol_canvas = FigureCanvasTkAgg(
            self.protocol_fig, master=self.graph_frame
        )
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Create figure for bandwidth usage
        self.bandwidth_fig = Figure(figsize=(6, 4))
        self.bandwidth_ax = self.bandwidth_fig.add_subplot(111)
        self.bandwidth_canvas = FigureCanvasTkAgg(
            self.bandwidth_fig, master=self.graph_frame
        )
        self.bandwidth_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Ayarlama işlemleriniz
        self.protocol_ax.set_aspect("equal")
        self.protocol_ax.axis("off")

    def animate_graphs(self):
        """Set up animation for real-time graphs"""
        self.protocol_animation = animation.FuncAnimation(
            self.protocol_fig,
            self.update_protocol_graph,
            interval=self.graph_update_interval,
            init_func=self.init_protocol_graph,
        )

        self.bandwidth_animation = animation.FuncAnimation(
            self.bandwidth_fig,
            self.update_bandwidth_graph,
            interval=self.graph_update_interval,
        )

    def init_protocol_graph(self):
        """Initialize the protocol distribution graph"""
        self.protocol_ax.clear()
        self.protocol_ax.set_aspect("equal")
        self.protocol_ax.axis("off")
        return []

    def update_graphs(self):
        self.update_protocol_graph()
        self.update_bandwidth_graph()

    def update_protocol_graph(self, frame=None):
        """Update protocol distribution pie chart"""
        self.protocol_ax.clear()
        protocols = self.stats["protocols"]
        if protocols:
            labels = list(protocols.keys())
            sizes = list(protocols.values())
            self.protocol_ax.pie(sizes, labels=labels, autopct="%1.1f%%")
            self.protocol_ax.set_aspect("equal")
            self.protocol_ax.axis("off")
            self.protocol_ax.set_title("Protocol Distribution")
        self.protocol_canvas.draw()

    def update_bandwidth_graph(self, frame=None):
        """Update bandwidth usage line graph"""
        self.bandwidth_ax.clear()
        for ip, sizes in self.stats["packet_sizes"].items():
            if sizes:
                self.bandwidth_ax.plot(sizes, label=ip)

        self.bandwidth_ax.set_title("Bandwidth Usage Over Time")
        self.bandwidth_ax.set_xlabel("Time")
        self.bandwidth_ax.set_ylabel("Packet Size (bytes)")
        self.bandwidth_ax.legend(loc="upper left", bbox_to_anchor=(1, 1))
        self.bandwidth_fig.tight_layout()
        self.bandwidth_canvas.draw()

    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Enhanced Network Analysis Tool")
        self.root.geometry("1600x1000")

        # Create main container
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel for controls and packet list
        left_panel = ttk.Frame(self.main_container)
        self.main_container.add(left_panel, weight=2)

        # Right panel for graphs and details
        right_panel = ttk.Frame(self.main_container)
        self.main_container.add(right_panel, weight=1)

        # Control panel
        self.setup_control_panel(left_panel)

        # Packet list
        self.setup_packet_list(left_panel)

        # Graphs panel
        self.setup_graphs_panel(right_panel)

        # Details panel
        self.setup_details_panel(right_panel)

    def setup_control_panel(self, parent):
        control_frame = ttk.LabelFrame(parent, text="Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Button frame
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(button_frame, text="Start", command=self.start_capture).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="Stop", command=self.stop_capture).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="Clear", command=self.clear_display).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="Report", command=self.generate_report).pack(
            side=tk.LEFT, padx=5
        )

        # Filter frame
        filter_frame = ttk.LabelFrame(control_frame, text="Filters")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        # Add protocol filter
        protocol_frame = ttk.Frame(filter_frame)
        protocol_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(protocol_frame, text="Protocol:").pack(side=tk.LEFT)
        self.protocol_filter_var = tk.StringVar()
        self.protocol_filter_combobox = ttk.Combobox(
            protocol_frame, textvariable=self.protocol_filter_var, width=10
        )
        self.protocol_filter_combobox["values"] = ("Any", "TCP", "UDP", "ICMP")
        self.protocol_filter_combobox.pack(side=tk.LEFT, padx=5)
        self.protocol_filter_combobox.current(0)
        self.protocol_filter_combobox.bind("<<ComboboxSelected>>", self.apply_filters)

        # Add packet size filter
        size_frame = ttk.Frame(filter_frame)
        size_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(size_frame, text="Packet Size:").pack(side=tk.LEFT)
        self.min_size_entry = ttk.Entry(size_frame, width=10)
        self.min_size_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(size_frame, text=" - ").pack(side=tk.LEFT)
        self.max_size_entry = ttk.Entry(size_frame, width=10)
        self.max_size_entry.pack(side=tk.LEFT, padx=5)

        # Port filter
        port_frame = ttk.Frame(filter_frame)
        port_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT)
        self.port_filter = ttk.Entry(port_frame, width=10)
        self.port_filter.pack(side=tk.LEFT, padx=5)

        # IP filters
        ip_frame = ttk.Frame(filter_frame)
        ip_frame.pack(fill=tk.X, padx=5, pady=2)

        # Source IP
        ttk.Label(ip_frame, text="Source IP:").pack(side=tk.LEFT)
        self.source_ip_filter = ttk.Entry(ip_frame, width=15)
        self.source_ip_filter.pack(side=tk.LEFT, padx=5)

        # Destination IP
        ttk.Label(ip_frame, text="Dest IP:").pack(side=tk.LEFT)
        self.dest_ip_filter = ttk.Entry(ip_frame, width=15)
        self.dest_ip_filter.pack(side=tk.LEFT, padx=5)

        # Apply filters button
        ttk.Button(ip_frame, text="Apply Filters", command=self.apply_filters).pack(
            side=tk.LEFT, padx=5
        )

    def setup_packet_list(self, parent):
        list_frame = ttk.LabelFrame(parent, text="Packet List")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Define columns
        columns = (
            "Time",
            "Protocol",
            "Source",
            "Destination",
            "Port",
            "Size",
            "Payload Preview",
            "raw_payload",
            "hex_dump",
        )
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show="headings")

        # Configure columns
        column_widths = {
            "Time": 80,
            "Protocol": 70,
            "Source": 120,
            "Destination": 120,
            "Port": 100,
            "Size": 80,
            "Payload Preview": 200,
        }

        for col in columns:
            if col in column_widths:
                self.packet_tree.heading(col, text=col)
                self.packet_tree.column(col, width=column_widths[col])
            else:
                self.packet_tree.heading(col, text=col)
                self.packet_tree.column(col, width=0, stretch=False)

        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview
        )
        x_scrollbar = ttk.Scrollbar(
            list_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview
        )

        self.packet_tree.configure(
            yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set
        )

        # Pack everything
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)

        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)

    def setup_graphs_panel(self, parent):
        self.graph_frame = ttk.LabelFrame(parent, text="Network Statistics")
        self.graph_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_details_panel(self, parent):
        details_frame = ttk.LabelFrame(parent, text="Packet Details")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Metadata section
        ttk.Label(details_frame, text="Metadata:").pack(fill=tk.X)
        self.metadata_text = scrolledtext.ScrolledText(details_frame, height=8)
        self.metadata_text.pack(fill=tk.BOTH, expand=True)

        # Hex view section
        ttk.Label(details_frame, text="Hex View:").pack(fill=tk.X)
        self.hex_text = scrolledtext.ScrolledText(
            details_frame, height=20, font=("Courier", 10)
        )
        self.hex_text.pack(fill=tk.BOTH, expand=True)

        # Payload Preview section
        ttk.Label(details_frame, text="Payload Preview:").pack(fill=tk.X)
        self.payload_preview_text = scrolledtext.ScrolledText(
            details_frame, height=8, font=("Courier", 10)
        )
        self.payload_preview_text.pack(fill=tk.BOTH, expand=True)

    def format_hex_display(self, raw_data):
        """Format raw data into traditional hex editor display"""
        if not raw_data:
            return "No payload data available"

        hex_per_line = 16
        result = []

        for i in range(0, len(raw_data), hex_per_line):
            chunk = raw_data[i : i + hex_per_line]
            offset = f"{i:08x}"
            hex_values = []
            ascii_chars = []

            for idx, byte in enumerate(chunk):
                hex_values.append(f"{byte:02x}")
                if idx == 7:
                    hex_values.append("")

                if 32 <= byte <= 126:
                    ascii_chars.append(chr(byte))
                else:
                    ascii_chars.append(".")

            while len(hex_values) < hex_per_line + 1:
                hex_values.append("  ")
                if len(hex_values) == 8:
                    hex_values.append("")

            while len(ascii_chars) < hex_per_line:
                ascii_chars.append(" ")

            hex_line = " ".join(hex_values)
            ascii_line = "".join(ascii_chars)
            result.append(f"{offset}  {hex_line}  |{ascii_line}|")

        return "\n".join(result)

    def extract_payload(self, packet):
        """Extract payload from packet and return both raw and formatted hex"""
        if Raw in packet:
            raw_data = packet[Raw].load
            hex_dump = self.format_hex_display(raw_data)
            ascii_preview = "".join(
                chr(b) if 32 <= b <= 126 else "." for b in raw_data[:100]
            )
            return raw_data, hex_dump, f"{ascii_preview}..."
        return None, None, "No payload"

    def check_port_filter(self, packet):
        """Check if packet matches port filter criteria"""
        current_port_filter = self.port_filter.get().strip()
        if not current_port_filter:
            return True

        try:
            filter_port = int(current_port_filter)
            if TCP in packet:
                return (
                    packet[TCP].sport == filter_port or packet[TCP].dport == filter_port
                )
            elif UDP in packet:
                return (
                    packet[UDP].sport == filter_port or packet[UDP].dport == filter_port
                )
            return False
        except ValueError:
            print("Invalid port number")
            return False

    def packet_callback(self, packet):
        if not self.capture_active:
            return

        if IP in packet:
            # Extract packet information
            timestamp = datetime.now().strftime("%H:%M:%S")
            ip_layer = packet[IP]

            # Check IP filters
            if not self.check_ip_filters(ip_layer.src, ip_layer.dst):
                return

            # Check protocol filter
            if not self.check_protocol_filter(packet):
                return

            # Check packet size filter
            packet_size = len(packet)
            if not self.check_packet_size_filter(packet_size):
                return

            protocol = "OTHER"
            src_port = "N/A"
            dst_port = "N/A"

            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"

            # Extract payload with hex formatting
            raw_payload, hex_dump, payload_preview = self.extract_payload(packet)

            # Update statistics
            self.stats["total_packets"] += 1
            self.stats["protocols"][protocol] += 1
            self.stats["ip_connections"][f"{ip_layer.src}->{ip_layer.dst}"] += 1

            # Update traffic history for graphs
            self.stats["traffic_history"][protocol].append(packet_size)
            self.stats["packet_sizes"][ip_layer.src].append(packet_size)

            # Limit history size
            max_history = 100
            if len(self.stats["packet_sizes"][ip_layer.src]) > max_history:
                self.stats["packet_sizes"][ip_layer.src] = self.stats["packet_sizes"][
                    ip_layer.src
                ][-max_history:]

            # Update GUI in main thread
            self.root.after(
                0,
                self.update_gui,
                timestamp,
                protocol,
                ip_layer.src,
                ip_layer.dst,
                f"{src_port}->{dst_port}",
                packet_size,
                payload_preview,
                raw_payload,
                hex_dump,
            )

            # Queue database operation
            self.db_queue.put(
                (
                    timestamp,
                    ip_layer.src,
                    ip_layer.dst,
                    protocol,
                    src_port,
                    dst_port,
                    raw_payload.hex() if raw_payload else None,
                    packet_size,
                )
            )

    def update_gui(
        self, time, proto, src, dst, ports, size, payload_preview, raw_payload, hex_dump
    ):
        """Update GUI with new packet information"""
        values = (
            time,
            proto,
            src,
            dst,
            ports,
            f"{size} bytes",
            payload_preview,
            raw_payload if raw_payload else "",
            hex_dump if hex_dump else "",
        )

        item = self.packet_tree.insert("", 0, values=values)

        # Limit displayed packets to prevent memory issues
        if len(self.packet_tree.get_children()) > 1000:
            last = self.packet_tree.get_children()[-1]
            self.packet_tree.delete(last)

    def show_packet_details(self, event):
        """Display detailed packet information when selected"""
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return

        selected_item = selected_items[0]
        values = self.packet_tree.item(selected_item)["values"]

        # Update metadata section
        metadata_text = f"""
    Time: {values[0]}
    Protocol: {values[1]}
    Source IP: {values[2]}
    Destination IP: {values[3]}
    Ports: {values[4]}
    Packet Size: {values[5]}
        """
        self.metadata_text.delete(1.0, tk.END)
        self.metadata_text.insert(tk.END, metadata_text)

        # Update hex view with stored hex dump
        hex_dump = values[8]  # Index 8 corresponds to hex_dump column
        self.hex_text.delete(1.0, tk.END)
        self.hex_text.insert(
            tk.END, hex_dump if hex_dump else "No payload data available"
        )

        # Update payload preview
        payload_preview = values[6]  # Index 6 corresponds to payload_preview column
        self.payload_preview_text.delete(1.0, tk.END)
        self.payload_preview_text.insert(
            tk.END, payload_preview if payload_preview else "No payload data available"
        )

    def update_filters(self):
        # Mevcut filtreleri temizle
        self.ip_filters["source"].clear()
        self.ip_filters["destination"].clear()
        self.protocol_filter.clear()
        self.packet_size_filter["min"] = None
        self.packet_size_filter["max"] = None

        # Yeni filtre değerlerini al
        source_ip = self.source_ip_filter.get().strip()
        dest_ip = self.dest_ip_filter.get().strip()
        protocol_filter = self.protocol_filter_var.get()
        min_size = self.min_size_entry.get().strip()
        max_size = self.max_size_entry.get().strip()

        # Kaynak IP filtresi uygula
        if source_ip:
            try:
                ipaddress.ip_address(source_ip)
                self.ip_filters["source"].add(source_ip)
            except ValueError:
                messagebox.showerror("Error", "Invalid source IP address")
                return

        # Hedef IP filtresi uygula
        if dest_ip:
            try:
                ipaddress.ip_address(dest_ip)
                self.ip_filters["destination"].add(dest_ip)
            except ValueError:
                messagebox.showerror("Error", "Invalid destination IP address")
                return

        # Protokol filtresi uygula
        if protocol_filter != "Any":
            self.protocol_filter.add(protocol_filter)

        # Paket boyutu filtresi uygula
        if min_size:
            try:
                self.packet_size_filter["min"] = int(min_size)
            except ValueError:
                messagebox.showerror("Error", "Invalid minimum packet size")
                return
        if max_size:
            try:
                self.packet_size_filter["max"] = int(max_size)
            except ValueError:
                messagebox.showerror("Error", "Invalid maximum packet size")
                return

        # Filtrelenmiş paketleri ağaca ekle
        self.update_packet_list()

        # Grafikleri güncelle
        self.update_graphs()

        messagebox.showinfo("Success", "Filters applied successfully")

    def update_packet_list(self):
        # Paket ağacını temizle
        self.packet_tree.delete(*self.packet_tree.get_children())

        # Filtrelenmiş paketleri ağaca ekle
        for packet in self.filtered_packets:
            (
                timestamp,
                proto,
                src,
                dst,
                ports,
                size,
                payload_preview,
                raw_payload,
                hex_dump,
            ) = packet
            values = (
                timestamp,
                proto,
                src,
                dst,
                ports,
                f"{size} bytes",
                payload_preview,
                raw_payload if raw_payload else "",
                hex_dump if hex_dump else "",
            )
            self.packet_tree.insert("", 0, values=values)

        # Görüntülenen paket sayısını sınırla
        if len(self.packet_tree.get_children()) > 1000:
            last = self.packet_tree.get_children()[-1]
            self.packet_tree.delete(last)

    def apply_filters(self, event=None):
        """Apply IP, protocol, and packet size filters"""
        self.update_filters()
        self.update_packet_list()
        # Clear existing filters
        self.ip_filters["source"].clear()
        self.ip_filters["destination"].clear()
        self.protocol_filter.clear()
        self.packet_size_filter["min"] = None
        self.packet_size_filter["max"] = None

        # Get filter values
        source_ip = self.source_ip_filter.get().strip()
        dest_ip = self.dest_ip_filter.get().strip()
        protocol_filter = self.protocol_filter_var.get()
        min_size = self.min_size_entry.get().strip()
        max_size = self.max_size_entry.get().strip()

        # Validate and apply source IP filter
        if source_ip:
            try:
                ipaddress.ip_address(source_ip)
                self.ip_filters["source"].add(source_ip)
            except ValueError:
                messagebox.showerror("Error", "Invalid source IP address")
                return

        # Validate and apply destination IP filter
        if dest_ip:
            try:
                ipaddress.ip_address(dest_ip)
                self.ip_filters["destination"].add(dest_ip)
            except ValueError:
                messagebox.showerror("Error", "Invalid destination IP address")
                return

        # Apply protocol filter
        if protocol_filter != "Any":
            self.protocol_filter.add(protocol_filter)

        # Apply packet size filter
        if min_size:
            try:
                self.packet_size_filter["min"] = int(min_size)
            except ValueError:
                messagebox.showerror("Error", "Invalid minimum packet size")
                return
        if max_size:
            try:
                self.packet_size_filter["max"] = int(max_size)
            except ValueError:
                messagebox.showerror("Error", "Invalid maximum packet size")
                return

        messagebox.showinfo("Success", "Filters applied successfully")

    def check_ip_filters(self, src_ip, dst_ip):
        """Check if packet matches IP filter criteria"""
        # If no filters are set, accept all packets
        if not self.ip_filters["source"] and not self.ip_filters["destination"]:
            return True

        # Check source IP filter
        if self.ip_filters["source"] and src_ip not in self.ip_filters["source"]:
            return False

        # Check destination IP filter
        if (
            self.ip_filters["destination"]
            and dst_ip not in self.ip_filters["destination"]
        ):
            return False

        return True

    def check_protocol_filter(self, packet):
        """Check if packet matches protocol filter criteria"""
        current_protocol_filter = self.protocol_filter_var.get()
        if current_protocol_filter == "Any":
            return True
        elif current_protocol_filter == "TCP" and TCP in packet:
            return True
        elif current_protocol_filter == "UDP" and UDP in packet:
            return True
        elif current_protocol_filter == "ICMP" and ICMP in packet:
            return True
        return False

    def check_packet_size_filter(self, packet_size):
        """Check if packet size matches the size filter criteria"""
        min_size = self.packet_size_filter["min"]
        max_size = self.packet_size_filter["max"]
        if min_size is not None and packet_size < min_size:
            return False
        if max_size is not None and packet_size > max_size:
            return False
        return True

    def start_capture(self):
        """Start packet capture"""
        if not self.capture_active:
            self.capture_active = True
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            print("Packet capture started...")

    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        print("Packet capture stopped.")

    def capture_packets(self):
        """Capture packets using scapy"""
        try:
            sniff(prn=self.packet_callback, store=0)
        except Exception as e:
            print(f"Capture error: {e}")
            self.capture_active = False

    def clear_display(self):
        """Clear the packet list, graphs, and reset statistics"""
        # Clear packet tree
        self.packet_tree.delete(*self.packet_tree.get_children())

        # Clear metadata, hex, and payload preview
        self.metadata_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        self.payload_preview_text.delete(1.0, tk.END)

        # Reset statistics
        self.stats = {
            "total_packets": 0,
            "protocols": defaultdict(int),
            "ip_connections": defaultdict(int),
            "ports": defaultdict(int),
            "traffic_history": defaultdict(list),
            "packet_sizes": defaultdict(list),
        }

        # Clear and reset protocol distribution graph
        self.protocol_ax.clear()
        self.protocol_ax.set_aspect("equal")
        self.protocol_ax.axis("off")
        self.protocol_canvas.draw()

        # Clear and reset bandwidth usage graph
        self.bandwidth_ax.clear()
        self.bandwidth_ax.set_title("Bandwidth Usage Over Time")
        self.bandwidth_ax.set_xlabel("Time")
        self.bandwidth_ax.set_ylabel("Packet Size (bytes)")
        self.bandwidth_ax.legend(loc="upper left", bbox_to_anchor=(1, 1))
        self.bandwidth_fig.tight_layout()
        self.bandwidth_canvas.draw()

    def generate_report(self):
        """Generate and display network analysis report"""
        report_window = tk.Toplevel(self.root)
        report_window.title("Network Analysis Report")
        report_window.geometry("600x400")

        report_text = scrolledtext.ScrolledText(report_window, wrap=tk.WORD)
        report_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        report = "\n=== Network Analysis Report ===\n"
        report += f"Total Packets: {self.stats['total_packets']}\n\n"

        report += "Protocol Distribution:\n"
        for proto, count in sorted(
            self.stats["protocols"].items(), key=lambda x: x[1], reverse=True
        ):
            report += f"{proto}: {count} packets\n"

        report += "\nMost Active IP Connections:\n"
        connections = sorted(
            self.stats["ip_connections"].items(), key=lambda x: x[1], reverse=True
        )[:10]
        for conn, count in connections:
            report += f"{conn}: {count} packets\n"

        report_text.insert(tk.END, report)
        report_text.configure(state="disabled")

    def __del__(self):
        """Cleanup when object is destroyed"""
        if hasattr(self, "db_queue"):
            self.db_queue.put(None)
            if hasattr(self, "db_thread"):
                self.db_thread.join()


analyzer = NetworkAnalyzer()
analyzer.root.mainloop()