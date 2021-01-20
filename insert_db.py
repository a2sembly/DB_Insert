import pymysql
from datetime import datetime
#!/usr/bin/env python
import socket
import struct
import re
import binascii


Data = []
#https://brownbears.tistory.com/432+++
#https://stackoverflow.com/questions/28154066/how-to-convert-datetime-to-integer-in-python?noredirect=1&lq=1
def Convert_dt_toInt(dt):
  return int(dt.strftime("%Y%m%d%H%M%S"))
#https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
def Convert_IP_toInt(strIP):
  try:
    return struct.unpack("!I", socket.inet_aton(strIP))[0]
  except:
    return struct.unpack("!I", socket.inet_aton(strIP))[0]

#https://gist.github.com/nlm/9ec20c78c4881cf23ed132ae59570340
def Convert_MAC_toInt(strMAC):
  res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', strMAC.lower())
  if res is None:
      raise ValueError('invalid mac address')#raise는 예외처리에 사용되며, 발생 시 바로 exception으로 넘어감.
  return int(res.group(0).replace(':', ''), 16)

def str_to_num(abc):
  num = 0
  a = [ord(i) for i in abc]
  for i in a:
      num = (num<<8)+i
  return num 

line_cnt = 0
if __name__ == '__main__':
  connection = pymysql.connect(host='localhost', user='a2sembly', password='toor', db='firewall_log', charset='utf8')
  cursor = connection.cursor()
  sql = "insert into firewall_log (dt, action, fwrule, src_id, src_ip, src_mac, src_port, dst_ip, dst_port, length) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
  logfile_path = "/home/bot/dbparser/BoB_DF_firewall.log"

  with open(logfile_path, 'r') as f:
    for line in f:
      if line_cnt >= 0:
        if str_to_num(line) == 10:
              continue
        else:
          try:
            log_parse = line.replace('\"','').replace(']','').replace('[','').split(' ')#H:%M:%S
            try:
              dt_obj = datetime.strptime(log_parse[0] + ' ' + log_parse[1], '%Y-%m-%d %H:%M:%S')
              dt_log = Convert_dt_toInt(dt_obj)
            except:
              line = line.encode().decode('utf-16-be')
              log_parse = line.replace('\"','').replace(']','').replace('[','').split(' ')#H:%M:%S
              dt_obj = datetime.strptime(log_parse[0] + ' ' + log_parse[1], '%Y-%m-%d %H:%M:%S')
              dt_log = Convert_dt_toInt(dt_obj)
            action = log_parse[6].split('=')[1]
            fwrule = int(log_parse[7].split('=')[1])
            src_id = log_parse[8].split('=')[1]
            src_ip = Convert_IP_toInt(log_parse[9].split('=')[1])
            src_mac = Convert_MAC_toInt(log_parse[10].split('=')[1])
            src_port = int(log_parse[11].split('=')[1])
            dst_ip = Convert_IP_toInt(log_parse[12].split('=')[1])
            dst_port = int(log_parse[13].split('=')[1])
            length = int(log_parse[14].split('=')[1])

            Data.append((dt_log, action, fwrule, src_id, src_ip, src_mac, src_port, dst_ip, dst_port, length))
          except Exception as e:
            print(line)
            with open('./error.log', 'a', newline='') as ef:
              ef.write("err_log : " + str(e) + "\n")
            ef.close()
            continue
        
        if len(Data) >= 1000000:
          cursor.executemany(sql, Data)
          connection.commit()
          Data.clear()
      else:
        line_cnt += 1
        continue

    if len(Data) >= 0:
        cursor.executemany(sql, Data)
        connection.commit()
        Data.clear()

  f.close()
  connection.close()
