# ctf-flag-in-pcap
用於搜尋 Flag 出現在Pcap 當中的哪個 TCP Stream 與 Pkt

# Readme
這個工具主要是因為我在打 CTF 的 A&D, 挨打的時候用來快速定位攻擊封包用的


# 使用方法
python find.py "attack.pcap" "flag 的 格式(re)"

# 範例
專案內有一個 xctf_2016_19.pcap 是我們在打 XCTF 2016 Final 時的被攻擊封包
比賽的 Flag 格式為 "[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+"

使用以下指令執行範例
python find.py "xctf_2016_19.pcap" "[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+"
