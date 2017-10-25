# -*- coding: utf-8 -*-
import socket,sys
import json,time
import struct,hashlib,select

AP_LOGIN_REQUEST = 0xf001
AP_LOGIN_REPLY = 0xf002
AP_HEART_REQUEST = 0xf003
AP_HEART_REPLY = 0xf004
AP_USE_INFO = 0xf005

#login config
login_request = {}
login_request['ap_mac']='00e04c20c1b0'
login_request['ap_ip']='192.168.1.2'
login_request['ap_mask']='255.255.255.0'
login_request['ap_gateway']='192.168.1.1'
login_request['ap_broadcast']='192.168.1.255'
login_request['ap_g24_valid']=1
login_request['ap_g24_standard']=10
login_request['ap_g24_channel']=6
login_request['ap_g24_bandwidth']=1
login_request['ap_g24_bind']=1
login_request['ap_g24_power']=1

login_request['ap_g5_valid']=1
login_request['ap_g5_standard']=10
login_request['ap_g5_channel']=6
login_request['ap_g5_bandwidth']=1
login_request['ap_g5_bind']=1
login_request['ap_g5_power']=1

login_request['ap_runtime']=60
login_request['ap_version']='test_verison'
login_request['ap_flash_status']='test'

#heart config
heart_request = {}
heart_request['ap_mac']='00e04c20c1b0'
heart_request['ap_ip']='192.168.1.2'
heart_request['ap_mask']='255.255.255.0'
heart_request['ap_gateway']='192.168.1.1'
heart_request['ap_broadcast']='192.168.1.255'

heart_request['ap_g24_valid']=1
heart_request['ap_g24_standard']=10
heart_request['ap_g24_channel']=6
heart_request['ap_g24_bandwidth']=1
heart_request['ap_g24_bind']=1
heart_request['ap_g24_power']=1

heart_request['ap_g5_valid']=1
heart_request['ap_g5_standard']=10
heart_request['ap_g5_channel']=6
heart_request['ap_g5_bandwidth']=1
heart_request['ap_g5_bind']=1
heart_request['ap_g5_power']=1

heart_request['ap_runtime']=60
heart_request['ap_version']='test_verison'
heart_request['ap_flash_status']='test'

#use config
use_info = {}
use_info['ap_mac']='00:e0:4c:20:c1:b0'
use_info['ap_g24_valid']=1
use_info['ap_g5_valid']=0
use_info['ap_g24_noise']=10
use_info['ap_g5_noise']=10
use_info['ap_g24_sta_num']=5
use_info['ap_g5_sta_num']=5

class AP_Traffic():
    rx_packets=10
    rx_bytes=10
    rx_retrys=10
    tx_packets=10
    tx_bytes=10
    tx_retrys=10
    tx_fail=10
    tx_drop=10
    
class AP_Sta_Info():   
    sta_mac='08104C012001'
    sta_rssi=5
    sta_rx_rate=10
    sta_rx_retry=10
    sta_tx_rate=10
    sta_tx_retry=10


class Ap():
    
    ROBOT_LIBRARY_SCOPE = 'TEST SUITE'
                
    def __init__(self,server_ip,client_ip):
        self._s_addr = (server_ip,20906)
        self.s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.s.setblocking(0)
        self.s.bind((client_ip,6720))
        
    def _recv(self,Token):
        infds,outfds,errfds = select.select([self.s],[],[],30)
        if len(infds):
            r_data, addr = self.s.recvfrom(2048)
            if len(r_data):
                token, result_type,result_len= struct.unpack('!8sii' ,r_data[0:16])
                result = struct.unpack('!'+str(result_len)+'s' ,r_data[16:])
                
                print 'result     token:'+ token[0:len(Token)] + ' token_len:'+ str(len(token)) +' packet_type:'+str(result_type)+' packet_length:'+str(result_len) + ' data:' + str(result)
        else:
            print "timeout!!!"
    
    def request(self,Token,Token_len,Packet_type,Packet_length,Data):
        data = json.dumps(Data,sort_keys=True)
        if Token_len == -1:
            token_len=8
        else:
            token_len=Token_len
            
        if Packet_length == -1:
            len_=len(data)
        else:
            len_=Packet_length

        buf=struct.pack('!'+str(token_len)+'sii'+str(len(data))+'s',Token,Packet_type,len_,data)

        print 'send       token:'+Token + ' token_len:'+ str(token_len) +' packet_type:'+str(Packet_type)+' packet_length:'+str(len_) + ' data:' + data
        self.s.sendto(buf,self._s_addr)
        
        if Packet_type!=AP_USE_INFO:
            self._recv(Token)
            
    def close(self):
        self.s.close()

def hashFromApTraffic(aptraffic):
    ap_hash={}
    ap_hash['rx_packets']=aptraffic.rx_packets
    ap_hash['rx_bytes']=aptraffic.rx_bytes
    ap_hash['rx_retrys']=aptraffic.rx_retrys
    ap_hash['tx_packets']=aptraffic.tx_packets
    
    ap_hash['tx_bytes']=aptraffic.tx_bytes
    ap_hash['tx_retrys']=aptraffic.tx_retrys
    ap_hash['tx_fail']=aptraffic.tx_fail
    ap_hash['tx_drop']=aptraffic.tx_drop
    
    return ap_hash

def hashFromSta(sta):    
    stahash={}
    stahash['sta_mac']=sta.sta_mac
    stahash['sta_rssi']=sta.sta_rssi
    stahash['sta_rx_rate']=sta.sta_rx_rate
    stahash['sta_rx_retry']=sta.sta_rx_retry
    stahash['sta_tx_rate']=sta.sta_tx_rate
    stahash['sta_tx_retry']=sta.sta_tx_retry
    return stahash
        
if __name__ == "__main__" :

    #输入服务端IP地址 和 调试的本机IP地址
    ap=Ap('192.168.1.1','192.168.1.2')
    
    #注册包
    ap.request(Token='netcore', Token_len=-1,Packet_type=AP_LOGIN_REQUEST, Packet_length=-1, Data=login_request)
    
    #心跳包
    ap.request(Token='netcore', Token_len=-1,Packet_type=AP_HEART_REQUEST,Packet_length=-1,Data=heart_request)
    
    #构建流量信息
    AP_Traffic_2G=AP_Traffic()
    
  #  AP_Traffic_2G.rx_bytes=
  #  AP_Traffic_2G.rx_packets=
  # AP_Traffic_2G.rx_retrys=
  #  AP_Traffic_2G.tx_bytes=
  #  AP_Traffic_2G.tx_drop=
  #  AP_Traffic_2G.tx_fail=
  #  AP_Traffic_2G.tx_packets=
  #  AP_Traffic_2G.tx_retrys=
    
    AP_Traffic_5G=AP_Traffic()
 #同上    

    ap_traffic_2g = hashFromApTraffic(AP_Traffic_2G)
    ap_traffic_5g = hashFromApTraffic(AP_Traffic_5G)
    
    use_info['ap_g24_traffic']=ap_traffic_2g
    use_info['ap_g5_traffic']=ap_traffic_5g

#构建STA信息        
    STA=AP_Sta_Info()
#
#    STA.sta_mac=
#    STA.sta_rssi=
#    STA.sta_rx_rate=
#    STA.sta_rx_retry=
#    STA.sta_tx_rate=
#    STA.sta_tx_retry=  
    sta=hashFromSta(STA)
    
    
    
    use_info['ap_g24_sta_info']=[]
    #通过append添加到对应的表中
    use_info['ap_g24_sta_info'].append(sta)
    use_info['ap_g5_sta_info']=[]
   # 通过append添加到对应的表中
    use_info['ap_g5_sta_info'].append(sta)
    #信息包
    ap.request(Token='netcore', Token_len=-1,Packet_type=AP_USE_INFO, Packet_length=-1, Data=use_info)
    ap.close()
    
    
    
    