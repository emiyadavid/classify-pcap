#coding:UTF-8
#author 陈嘉豪

from scapy.all import *
import collections
import scapy
import pymysql

from scapy.utils import PcapReader, PcapWriter
import gzip,zlib,cPickle
import time
from mkdir_file import *
import struct
import time

#检测ip
def ip_get(pcap):
    ip=[]
    if pcap.haslayer(IP):
        dst = pcap.getlayer(IP).dst
        src = pcap.getlayer(IP).src
        ip.append(src)
        ip.append(dst)
        return ip
    else:
        dst = "0.0.0.0"
        src = "0.0.0.0"
        ip.append(src)
        ip.append(dst)
        return ip

#端口检测
def port_get(pcap):
    port=[]
    if pcap.haslayer(TCP):
        tcp = pcap.getlayer(TCP)
        dport = int(tcp.dport)
        sport = int(tcp.sport)
        port.append(sport)
        port.append(dport)
        return port

    elif pcap.haslayer(UDP):
        udp = pcap.getlayer(UDP)
        dport = int(udp.dport)
        sport = int(udp.sport)
        port.append(sport)
        port.append(dport)
        return port

    else:
        dport = 0
        sport = 0
        port.append(sport)
        port.append(dport)
        return port

#时间获取
def time_get(pcap):
    #ptime = pcap.payload
    time =  pcap.time
    return time

if __name__ == '__main__':
    #连接数据库
    conn = pymysql.connect(host='127.0.0.1',port = 3306, user = 'root', passwd = '123456', db = 'ids')
    #创建游标
    cur = conn.cursor()

    origin_pcap_name = 'Thursday-WorkingHours.pcap'
    rootpath = "classification\\"
    pcap_path =  'CICIDS2017/' + origin_pcap_name
    print "read file......"
    t0 = time.clock()
    print "start"

    table_name = ""

    for p in PcapReader(pcap_path):

        src_ip = ip_get(p)[0]
        dst_ip = ip_get(p)[1]
        src_port = port_get(p)[0]
        dst_port = port_get(p)[1]
        catch_time = float(time_get(p))
        print catch_time
        timeArray = time.localtime(catch_time)
        otherStyleTime = time.strftime("%d/%m/%Y %H:%M", timeArray)
        Timestap = str(otherStyleTime)
        print Timestap

        sql = "SELECT Label, id FROM cic2017_webattack WHERE Source_IP = '%s' AND Source_Port = '%s' AND Destination_IP = '%s' AND Destination_Port = '%s' " % (src_ip, src_port, dst_ip, dst_port )
        row_count = cur.execute(sql)
        ret = cur.fetchone()

        if row_count != 0:
            subpath = rootpath + ret[0].strip() + "\\"
            mkdir(subpath)
            attack_pcap_name = 'classification/'+ ret[0].strip() + "/" + ret[0].strip() + '_' + str(ret[1]) + '.pcap'


            writer = PcapWriter(attack_pcap_name, append = True)
            writer.write(p)

            writer.flush()
            writer.close()

        print "ok"


    conn.commit()
    cur.close()
    conn.close()

    print "end"
    print time.clock() - t0
