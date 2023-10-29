import sys
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUiType
from PyQt5 import QtCore
import os
import threading
import libpcap as pcap
import ctypes as ct
from parse import analyze_packet


def hex_to_ascii(hex_data):
    ascii_data = ''
    hex_data = hex_data.replace(' ', '')
    for i in range(0, len(hex_data), 2):
        ascii_data += chr(int(hex_data[i:i + 2], 16))
    return ascii_data


def extract(info):
    try:
        ts = info["time"]
        length = info["eth"]["eth_frame_len"]
        p_n = "ipv4" if ("ip" in info and info["ip"]["ip_version"] == 4) else (
            "arp" if "arp" in info else "ipv6")
        p_n = "icmp6" if "icmp6" in info else ("icmp" if "icmp" in info else p_n)
        p_t = "tcp" if "tcp" in info else ("udp" if "udp" in info else " ")
        p_a = "dns" if "dns" in info else ("https" if "https" in info else ("http" if "http" in info else " "))
        source = info["ip"]["ip_source_address"] if "ip" in info else (info["arp"]["arp_sender_protocol_address"] if "arp" in info else " ")
        destination = info["ip"]["ip_destination_address"] if "ip" in info else (info["arp"]["arp_target_protocol_address"] if "arp" in info else " ")
        if "tcp" in info:
            source = source + ":" + info["tcp"]["tcp_source_port"]
            destination = destination + ":" + info["tcp"]["tcp_destination_port"]
        elif "udp" in info:
            source = source + ":" + info["udp"]["source_port"]
            destination = destination + ":" + info["udp"]["destination_port"]
        data = info["raw_data"]
        return ts, length, p_n, p_t, p_a, source, destination, data
    except Exception as e:
        print(e)


def hex_ascii(data):
    hex_data = [format(x, '02x') for x in data]
    ascii_data = [chr(x) if 32 <= x <= 126 else '.' for x in data]
    all_text = ''
    hex_text = ''
    ascii_text = ''
    cnt = 0
    for i in range(len(hex_data)):
        hex_text += (hex_data[i] + ' ')
        ascii_text += ascii_data[i]
        cnt += 1
        if cnt % 16 == 0:
            all_text += (hex_text + '     ' + ascii_text)
            all_text += '\n'
            hex_text = ''
            ascii_text = ''
    num = cnt % 16
    if num != 0:
        all_text += (hex_text + (16 - num) * 3 * ' ' + '     ' + ascii_text)
    return all_text


gui, _ = loadUiType('sniffer_new.ui')


class APP(QMainWindow, gui):
    def __init__(self):
        QMainWindow.__init__(self)
        self.errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        self.interfaces = {}
        self.interface = b''
        self.handle = None
        self.localnet = pcap.bpf_u_int32()
        self.netmask = pcap.bpf_u_int32()
        self.thread = None
        self.bpf_filter = ''
        self.parsed_infos = []
        self.pcap_data = []
        self.track_id = -1
        self.track_condition = ''
        self.init()

    def init(self):
        self.filter = pcap.bpf_program()
        alldevs = ct.POINTER(pcap.pcap_if_t)()
        pcap.findalldevs(ct.byref(alldevs), self.errbuf)
        if self.errbuf.value:
            print("find devs error :", self.errbuf.value, "\n\n")
            exit()
        devs = alldevs
        while devs:
            self.interfaces[devs.contents.description.decode()] = devs.contents.name
            devs = devs.contents.next
        pcap.freealldevs(alldevs)
        # self.interface = b'\\Device\\NPF_{3A61B63B-97BE-4CEE-97D9-6F51695335E6}'
        self.init_ui()

    def init_ui(self):
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setupUi(self)
        self.move(100, 100)
        style = open("themes/darkorange.css", 'r')
        style = style.read()
        self.setStyleSheet(style)

        self.interfaces_combo.addItems([x for x in self.interfaces])
        self.interfaces_combo.currentIndexChanged.connect(self.interface_changed)
        self.open.clicked.connect(self.import_pcap)
        self.save.clicked.connect(self.save_packets)
        self.bpf_label.setText("Input BPF:")
        self.bpf_edit.textChanged[str].connect(self.bpf_change)
        self.start.clicked.connect(self.start_sniffer)
        self.stop.clicked.connect(self.stop_sniffer)
        self.clear.clicked.connect(self.clear_packets)
        self.tableWidget.setColumnCount(8)
        font = QFont()
        font.setPointSize(14)
        self.tableWidget.horizontalHeader().setFont(font)
        self.tableWidget.setHorizontalHeaderLabels(["Timestamp", "Length", "Network Protocol", "Transport Protocol",
                                                    "Application Protocol", "Source", "Destination", "Data"])
        # 自适应列宽
        self.tableWidget.resizeColumnsToContents()
        # 设置第一列的大小模式为Interactive
        self.tableWidget.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableWidget.itemSelectionChanged.connect(self.packet_selected)
        self.raw.setReadOnly(True)
        self.treeWidget.setHeaderHidden(True)
        header = self.treeWidget.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(False)
        self.close_button.clicked.connect(self.close)
        self.track.clicked.connect(self.track_stream)

        # self.setWindowTitle("Sniffer")
        # self.show()

    def interface_changed(self):
        self.interface = self.interfaces[self.interfaces_combo.currentText()]
        print("chose interface: ", self.interface.decode())
        self.handle = pcap.open_live(self.interface, 65535, 1, 1000, self.errbuf)
        if self.errbuf.value:
            print("hanle error :", self.errbuf.value)
            return
        else:
            print("open live handle: ", self.handle)

    def packet_handler(self, _, header, pkt_data):
        s = ct.string_at(pkt_data, header.contents.len)
        info = analyze_packet(s)
        info["time"] = str(header.contents.ts.tv_sec) + '.' + str(header.contents.ts.tv_usec)
        self.parsed_infos.append(info)
        self.pcap_data.append([header, pkt_data])
        self.update_packet_table()

    def capture(self):
        PacketHandlerFunction = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pcap.pkthdr),
                                             ct.POINTER(ct.c_ubyte))
        packet_handler_function = PacketHandlerFunction(self.packet_handler)
        pcap.loop(self.handle, -1, packet_handler_function, None)

    def start_sniffer(self):
        self.handle = pcap.open_live(self.interface, 65535, 1, 1000, self.errbuf)
        if self.errbuf.value:
            print("hanle error :", self.errbuf.value)
            return
        else:
            print("open live handle: ", self.handle)
        if pcap.lookupnet(self.interface, ct.byref(self.localnet), ct.byref(self.netmask), self.errbuf) < 0:
            print("lookupnet error")
            return
        print("local net: ", self.localnet)
        print("netmask: ", self.netmask)
        if self.track_condition == '':
            self.bpf_filter = self.bpf_edit.text()
        else:
            self.bpf_filter = self.track_condition
        print(self.bpf_filter)
        if not self.interface:
            print("please chose interface")
            return
        if self.bpf_filter:
            cmdbuf = self.bpf_filter.encode("utf-8")
            if pcap.compile(self.handle, ct.byref(self.filter), cmdbuf, 1, self.netmask) < 0:
                print("compile: ", pcap.geterr(self.handle).decode("utf-8", "ignore"))
                QMessageBox.information(self, 'Warning', "bpf expression invalid!")
                return
            if pcap.setfilter(self.handle, ct.byref(self.filter)) < 0:
                print("filter: ", pcap.geterr(self.handle).decode("utf-8", "ignore"))
                QMessageBox.information(self, 'Warning', "bpf expression invalid!")
                return
        print("live cap begin(loop)")
        # 使用loop函数进行抓包，设置回调函数的实例
        self.thread = threading.Thread(target=self.capture)
        print("thread start")
        self.thread.start()

    def stop_sniffer(self):
        if not self.handle:
            print("not working")
            return
        pcap.breakloop(self.handle)
        self.thread.join()
        print("live cap end(loop)")

    def update_packet_table(self):
        info = self.parsed_infos[len(self.parsed_infos) - 1]
        ts, length, p_n, p_t, p_a, source, destination, data = extract(info)
        row_num = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row_num)
        self.tableWidget.setItem(row_num, 0, QTableWidgetItem(ts))
        self.tableWidget.setItem(row_num, 1, QTableWidgetItem(str(length)))
        self.tableWidget.setItem(row_num, 2, QTableWidgetItem(p_n))
        self.tableWidget.setItem(row_num, 3, QTableWidgetItem(p_t))
        self.tableWidget.setItem(row_num, 4, QTableWidgetItem(p_a))
        self.tableWidget.setItem(row_num, 5, QTableWidgetItem(source))
        self.tableWidget.setItem(row_num, 6, QTableWidgetItem(destination))
        self.tableWidget.setItem(row_num, 7, QTableWidgetItem(str(data)))

    def clear_packets(self):
        print("clear")
        self.bpf_filter = ''
        self.pcap_data = []
        self.parsed_infos = []
        self.tableWidget.setRowCount(0)
        self.raw.clear()
        self.treeWidget.clear()
        self.track_id = -1
        self.track_condition = ''

    def fill_item(self, item, value):
        # 如果值是一个字典
        if type(value) is dict:
            # for key, val in value.items():
            #     if
            # 遍历字典的键和值
            for key, val in value.items():
                if key == "time" or key == "raw_data":
                    continue
                # 创建一个子节点
                child = QTreeWidgetItem()
                if type(val) is not dict:
                    child.setText(0, str(key) + " :  " + str(val))
                else:
                    child.setText(0, str(key))
                # 把子节点添加到当前节点下
                item.addChild(child)
                # 递归地调用这个函数，把值填充到子节点中
                self.fill_item(child, val)

    # 定义一个函数，用于把字典数据填充到树形组件中
    def fill_widget(self, widget, value):
        # 清空树形组件中的所有内容
        widget.clear()
        # 调用上面定义的函数，把字典数据填充到根节点中
        self.fill_item(widget.invisibleRootItem(), value)

    def packet_selected(self):
        selected_items = self.tableWidget.selectedItems()
        if not selected_items:
            return
        selected_row = selected_items[0].row()
        self.track_id = selected_row
        packet_info = self.parsed_infos[selected_row]
        all_text = hex_ascii(packet_info["raw_data"])
        self.raw.setPlainText(all_text)
        self.fill_widget(self.treeWidget, packet_info)

    def import_pcap(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open pcap file", str(os.getcwd()))
        if file_name and (file_name.endswith(".pcap") or file_name.endswith(".cap")):
            file_name = bytes(file_name, "utf-8")
            print(file_name)
            fin = pcap.open_offline(file_name, self.errbuf)
            if self.errbuf.value:
                print(self.errbuf.value)
                return
            pheader = pcap.pkthdr()
            while True:
                packet = pcap.next(fin, pheader)
                if not packet:
                    break
                info = analyze_packet(ct.string_at(packet, pheader.len))
                info["time"] = str(pheader.ts.tv_sec) + '.' + str(pheader.ts.tv_usec)
                self.parsed_infos.append(info)
                self.pcap_data.append([pheader, packet])
                self.update_packet_table()
            pcap.close(fin)
        else:
            print("invalid file")

    def save_packets(self):
        if not self.handle:
            print("can not save data from file")
            return
        file_name, _ = QFileDialog.getSaveFileName(self, "Save packets", str(os.getcwd()))
        if file_name and (file_name.endswith(".pcap") or file_name.endswith(".cap")):
            file_name = bytes(file_name, "utf-8")
            fPcap = pcap.dump_open(self.handle, file_name)
            i = 0
            for header, packet in self.pcap_data:
                print(f"save id {i}")
                print(header, packet)
                i += 1
                fPcapUbyte = ct.cast(fPcap, ct.POINTER(ct.c_ubyte))
                pcap.dump(fPcapUbyte, header, packet)
            pcap.dump_flush(fPcap)
            pcap.dump_close(fPcap)
            print("save over")
        else:
            print("invalid filename")

    def bpf_change(self):
        if not self.handle:
            print("no handle")
            return
        self.bpf_filter = self.bpf_edit.text()
        if self.bpf_filter:
            cmdbuf = self.bpf_filter.encode("utf-8")
            bpf_invalid = 0
            if pcap.compile(self.handle, ct.byref(self.filter), cmdbuf, 1, self.netmask) < 0:
                bpf_invalid = 1
            if bpf_invalid == 1:
                self.bpf_label.setText("Invalid!")
            else:
                self.bpf_label.setText("Valid!")
        else:
            self.bpf_label.setText("Input BPF:")

    def track_stream(self):
        if self.track_id == -1:
            QMessageBox.information(self, 'Warning', "Please select the item!")
            print("No selected item")
            return
        if self.handle:
            self.stop_sniffer()
        track_info = self.parsed_infos[self.track_id]
        _, _, _, _p, _, _s, _d, _ = extract(track_info)
        if _p == " ":
            print("no udp or tcp")
            QMessageBox.information(self, 'Warning', "Can only track TCP or UDP")
            return
        self.clear_packets()
        self.track_id = 1
        self.track_condition = f"{_p} and ( (src host {_s.split(':')[0]} and dst host {_d.split(':')[0]} and src port {_s.split(':')[1]} and dst port {_d.split(':')[1]}) or (src host {_d.split(':')[0]} and dst host {_s.split(':')[0]} and src port {_d.split(':')[1]} and dst port {_s.split(':')[1]}) )"
        self.start_sniffer()

    def mousePressEvent(self, e):
        if e.button() == QtCore.Qt.LeftButton:
            self.m_drag = True
            self.m_DragPosition = e.globalPos() - self.pos()
            e.accept()

    def mouseReleaseEvent(self, e):
        if e.button() == QtCore.Qt.LeftButton:
            self.m_drag = False

    def mouseMoveEvent(self, e):
        try:
            if QtCore.Qt.LeftButton and self.m_drag:
                self.move(e.globalPos() - self.m_DragPosition)
                e.accept()
        except:
            print("error")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = APP()
    window.show()
    app.exec_()
