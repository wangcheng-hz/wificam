#!/usr/bin/env python
import os, sys
import commands
import redis
import logger
import IP

curr_path = os.getcwd()
if os.path.abspath(curr_path) not in sys.path:
    sys.path.append(os.path.abspath(curr_path))

download_str = "http://ips.chacuo.net/down/t_txt=p_"
city_list = {"BJ":"BeiJing",
             "HB":"Hubei",
             "GD":"Guangdong",
             "SD":"ShanDong",
             "ZJ":"ZheJing",
             "JS":"JiangSu",
             "SH":"ShangHai",
             "LN":"LiaoNing",
             "SC":"SiChuan",
             "HA":"HeNan",
             "FJ":"FuJian",
             "HN":"HuNan",
             "HE":"HeiBei",
             "CQ":"CongQing",
             "SX":"ShanXi",
             "JX":"JiangXi",
             "SN":"SanXi",
             "AH":"AnHui",
             "HL":"HeiLongJiang",
             "GX":"GuangXi",
             "JL":"JiLing",
             "YN":"YunNan",
             "TJ":"TianJin",
             "NM":"NeiMengGu",
             "XJ":"XinJiang",
             "GS":"GanSu",
             "GZ":"GuiZhou",
             "HI":"HaiNan",
             "NX":"NingXia",
             "QH":"QingHai",
             "XZ":"XiZang",
             "HK":"HongKong"}


def wificam_execute_cmd(str):
    status, output = commands.getstatusoutput(str)
    if (status):
        logger.err("cmd:%s execute failed:%d, outputs:%s" % ( str, status, output))

def download_ipaddr_range():
    for key in city_list:
        cmd = "wget %s%s" % (download_str, key)
        wificam_execute_cmd(cmd)

def read_one_line_from_file(file):
    with open(file, 'rb') as f:
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                return

def write_to_redis_zadd(key, s, score):
    conn = redis.Redis("127.0.0.1", 6379)
    conn.zadd(key, s, score)

def clean_all_keys():
    conn = redis.Redis("127.0.0.1", 6379)
    for key in city_list:
        conn.delete(key)    

def parse_one_line_ipaddr(key, s):
    list = s.split()
    if len(list) < 3:
        logger.info("invalid ip addr range:%s" % s)
        return
    s = "%s %s" % (list[0], list[1])
    score = IP.IP(list[0]).int()
    write_to_redis_zadd("city-%s"%key, s, score)

def parse_ipaddr_range():
    for key in city_list:
        filename = "%s/t_txt=p_%s" % (curr_path, key)
        line = read_one_line_from_file(filename)
        for s in line:
            parse_one_line_ipaddr(key, s)


def isValidIpAddr(str):
    if (len(str)) < len("0.0.0.0") or (len(str)) > len("255.255.255.255"):
        return False
    try:
        IP.IP(str)
    except:
        return False
    return True

def scan_valid_ipaddr(city=None):
    scan_port = [80, 81, 8081, 8888]
    conn = redis.Redis("127.0.0.1", 6379)
    redis_keys = []
    if city:
        redis_keys.append(city)
    else:
        redis_keys = conn.keys("city-*")
        
    for key in redis_keys:     #scaning city
        ip_list = conn.zrange(key, 0, -1)
        for ip in ip_list:     #scaning ip ranges
            redis_str = '-'.join(ip.split())
            zmap_str = IP.IP(redis_str).strNormal()
            for port in scan_port:   #scaning for potential camera port
                redis_cmd = "zmap -p %d %s 8 -i ens3f0" % (port, zmap_str)
                logger.info(redis_cmd)
                __, output = commands.getstatusoutput(redis_cmd)
                raw_iplist = output.split()
                for raw_ip in raw_iplist:   #parse valid ip addr
                    if isValidIpAddr(raw_ip):
                        store_key = "raw-ip-for-%s" % key
                        store_str = "%s:%d" % (raw_ip, port)
                        store_score = IP.IP(raw_ip).int()
                        conn.zadd(store_key, store_str, store_score)


if __name__ == "__main__":
    #download_ipaddr_range()
    clean_all_keys()
    parse_ipaddr_range()
    scan_valid_ipaddr()
