#!/usr/bin/env python
# -*- coding: utf-8 -*-  

import socket,traceback,sys,json,time,os,signal
import logging,select
import threading,struct,copy
import ConfigParser,random
import logging
import multiprocessing
import BaseHTTPServer
import cgi

AP_LOGIN_REQUEST = 0xf001
AP_LOGIN_REPLY = 0xf002
AP_HEART_REQUEST = 0xf003
AP_HEART_REPLY = 0xf004
AP_USE_INFO = 0xf005

is_exit = False

Theads = []
web_list = []

def signal_init(signum, frame):
    global is_exit
    print '程序准备终结者中。\n'
    is_exit = True
    print "指令设置完毕，虚拟AP正在逐步停止中，请耐心等待\n"
    
class ConfigSystem():
    _cf = ''
    _basic_data = {}
    _use_data = {}
    _ap_traffic={}
    _ap_sta_info={}
    _ap_sta_info_5g={}
    _ap_list = []
    
    _login_heart_list={}
    _user_info_list={}
    def __init__(self,config):
        self._cf = ConfigParser.ConfigParser()
        self._cf.read(config)
        self._basic_data={}
        self._basic_data['ap_g24_valid']=self._cf.getint("BasicData","ap_g24_valid")
        self._basic_data['ap_g24_standard']=self._cf.getint("BasicData","ap_g24_standard")
        self._basic_data['ap_g24_channel']=self._cf.getint("BasicData","ap_g24_channel")
        self._basic_data['ap_g24_bandwidth']=self._cf.getint("BasicData","ap_g24_bandwidth")
        self._basic_data['ap_g24_bind']=self._cf.getint("BasicData","ap_g24_bind")
        self._basic_data['ap_g24_power']=self._cf.getint("BasicData","ap_g24_power")
        self._basic_data['ap_g5_valid']=self._cf.getint("BasicData","ap_g5_valid")
        self._basic_data['ap_g5_standard']=self._cf.getint("BasicData","ap_g5_standard")
        self._basic_data['ap_g5_channel']=self._cf.getint("BasicData","ap_g5_channel")
        self._basic_data['ap_g5_bandwidth']=self._cf.getint("BasicData","ap_g5_bandwidth")
        self._basic_data['ap_g5_bind']=self._cf.getint("BasicData","ap_g5_bind")
        self._basic_data['ap_g5_power']=self._cf.getint("BasicData","ap_g5_power")
        self._basic_data['ap_runtime']=self._cf.getint("BasicData","ap_runtime")
        self._basic_data['ap_version']=self._cf.get("BasicData","ap_version")
        self._basic_data['ap_flash_status']=self._cf.get("BasicData","ap_flash_status")
        self._basic_data['ap_mimo']=self._cf.get("BasicData","ap_mimo")
        
        self._use_data['ap_mac']  = ''
        self._use_data['ap_g24_valid']=self._cf.getint("UserData","ap_g24_valid")
        self._use_data['ap_g5_valid']=self._cf.getint("UserData","ap_g5_valid")
        self._use_data['ap_g24_noise']=self._cf.getint("UserData","ap_g24_noise")
        self._use_data['ap_g5_noise']=self._cf.getint("UserData","ap_g5_noise")
        self._use_data['ap_g24_sta_num']=self._cf.get("UserData","ap_g24_sta_num")
        self._use_data['ap_g5_sta_num']=self._cf.get("UserData","ap_g5_sta_num")
    
        self._ap_traffic['rx_packets']=self._cf.getint("APTraffic","rx_packets")
        self._ap_traffic['rx_bytes']=self._cf.getint("APTraffic","rx_bytes")
        self._ap_traffic['rx_retrys']=self._cf.getint("APTraffic","rx_retrys")
        self._ap_traffic['tx_packets']=self._cf.getint("APTraffic","tx_packets")  
        self._ap_traffic['tx_bytes']=self._cf.getint("APTraffic","tx_bytes")
        self._ap_traffic['tx_retrys']=self._cf.getint("APTraffic","tx_retrys")
        self._ap_traffic['tx_fail']=self._cf.getint("APTraffic","tx_fail")
        self._ap_traffic['tx_drop']=self._cf.getint("APTraffic","tx_drop")
	self._ap_traffic['utilization']=self._cf.getint("APTraffic","utilization")
	self._ap_traffic['bss_utilization']=self._cf.getint("APTraffic","bss_utilization")
	self._ap_traffic['Idle']=self._cf.getint("APTraffic","Idle")
      
	self._ap_sta_info['sta_rssi']=self._cf.get("APStaInfo","sta_rssi")        
	self._ap_sta_info['sta_mimorssi0']=self._cf.get("APStaInfo","sta_mimorssi0")
	self._ap_sta_info['sta_mimorssi1']=self._cf.get("APStaInfo","sta_mimorssi1")
        self._ap_sta_info['sta_rx_rate']=self._cf.get("APStaInfo","sta_rx_rate")
        self._ap_sta_info['sta_rx_retry']=self._cf.get("APStaInfo","sta_rx_retry")
        self._ap_sta_info['sta_tx_rate']=self._cf.get("APStaInfo","sta_tx_rate")
        self._ap_sta_info['sta_tx_retry']=self._cf.get("APStaInfo","sta_tx_retry")
	self._ap_sta_info['tx_avarage']=self._cf.get("APStaInfo","tx_avarage")
	self._ap_sta_info['rx_avarage']=self._cf.get("APStaInfo","rx_avarage")
        self._ap_sta_info['vwlan_idx']=self._cf.getint("APStaInfo","vwlan_idx")
        self._ap_sta_info['network']=self._cf.getint("APStaInfo","network")

        self._ap_sta_info_5g['sta_rssi']=self._cf.get("APStaInfo5G","sta_rssi")
	self._ap_sta_info_5g['sta_mimorssi0']=self._cf.get("APStaInfo5G","sta_mimorssi0")
	self._ap_sta_info_5g['sta_mimorssi1']=self._cf.get("APStaInfo5G","sta_mimorssi1")
        self._ap_sta_info_5g['sta_rx_rate']=self._cf.get("APStaInfo5G","sta_rx_rate")
        self._ap_sta_info_5g['sta_rx_retry']=self._cf.get("APStaInfo5G","sta_rx_retry")
        self._ap_sta_info_5g['sta_tx_rate']=self._cf.get("APStaInfo5G","sta_tx_rate")
        self._ap_sta_info_5g['sta_tx_retry']=self._cf.get("APStaInfo5G","sta_tx_retry")
	self._ap_sta_info_5g['tx_avarage']=self._cf.get("APStaInfo5G","tx_avarage")
	self._ap_sta_info_5g['rx_avarage']=self._cf.get("APStaInfo5G","rx_avarage")
        self._ap_sta_info_5g['vwlan_idx']=self._cf.getint("APStaInfo5G","vwlan_idx")
        self._ap_sta_info_5g['network']=self._cf.getint("APStaInfo5G","network")
        
        
        self._ac_ip =  self._cf.get("global", "ac_ip")
        self._eth = self._cf.get("global", "eth")
        self._ac_mask =self._cf.getint("global", "mask")
        self._heart_time = self._cf.getint("global", "heart_time")
        self._ap_num = self._cf.getint("global", "ap_num")
        
        self._wait_time=self._cf.getint("global", "wait_time")
        self._inter_time=self._cf.getfloat("global", "inter_time")
        self._cgi_enable=self._cf.getint("global", "cgi_enable")
        self._cgi_response=self._cf.get("global", "cgi_response")
        
        
        self._sta_item=self._cf.items("StaMac")

    def getIntertime(self):
        return self._inter_time

    def getEnable(self):
        return self._cgi_enable
    
    def getHeartTime(self):
        return self._heart_time
    
    def getIpList(self):
        return self._ap_list
    
    def getBroadcast(self):
        return self._broadcast
    
    def getWaitTime(self):
        return self._wait_time
    
    def getCgiResponse(self):
        return self._cgi_response    
        
    def ConfigIp(self):
        mask =0
        ip = socket.ntohl(struct.unpack("I",socket.inet_aton(str(self._ac_ip)))[0])

        for v in range(1,32-self._ac_mask+1):
            mask = mask << 1 | 1

        broadcast= ip | mask
        net = broadcast ^mask
        mask=0X00
        
        for v in range(1,32-self._ac_mask+1):
            mask = mask << 1        
        self._broadcast = socket.inet_ntoa(struct.pack('I',socket.htonl(broadcast)))
        self._mask = socket.inet_ntoa(struct.pack('I',socket.htonl(mask)))
    
        ip_addr=net + 100
        for i in range(0,self._ap_num):
            ip_addr= ip_addr + 1
            ip = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
            self._ap_list.append(ip)
            cmd="ip addr add " + ip + "/" +str(self._ac_mask) + " dev " + self._eth
            os.system(cmd)
                    
    def DeleteIp(self,ip):
        cmd="ip addr del " + ip + "/" +str(self._ac_mask) + " dev " + self._eth
        os.system(cmd)
        print ip+"-ap close"
    
    def _switchhex(self,af_mac):
        after_mac=str(hex(af_mac))[2:]
        for v in range(1,8-len(after_mac)-1):
            after_mac='0'+ after_mac
        return after_mac
    
    def GetloginHeartList(self):
        
        pre_mac='003333'
        start_mac=0x1
        for ip in self._ap_list: 
            copydata = copy.deepcopy(self._basic_data)
            copydata['ap_mac']=pre_mac+self._switchhex(start_mac)
            copydata['ap_ip']=ip
            copydata['ap_mask']=self._mask
            copydata['ap_gateway']=self._ac_ip
            copydata['ap_broadcast']=self._broadcast
            self._login_heart_list[ip]=copydata
            start_mac=start_mac+1
            
        return self._login_heart_list         
    
    def GetUserInfoList(self):
       
	rssi_start=int(self._ap_sta_info['sta_rssi'].split('-')[0])  	
	rssi_end=int(self._ap_sta_info['sta_rssi'].split('-')[1])
  	rssi0_start=int(self._ap_sta_info['sta_mimorssi0'].split('-')[0])
        rssi0_end=int(self._ap_sta_info['sta_mimorssi0'].split('-')[1])
	rssi1_start=int(self._ap_sta_info['sta_mimorssi1'].split('-')[0])
	rssi1_end=int(self._ap_sta_info['sta_mimorssi1'].split('-')[1])
        
        rx_rate_list=self._ap_sta_info['sta_rx_rate'].split(',')
        rx_retry_list=self._ap_sta_info['sta_rx_retry'].split(',')
        
        tx_rate_list=self._ap_sta_info['sta_tx_rate'].split(',')
        tx_retry_list=self._ap_sta_info['sta_tx_retry'].split(',')
        tx_avarage_list=self._ap_sta_info['tx_avarage'].split(',')
	rx_avarage_list=self._ap_sta_info['rx_avarage'].split(',')
	rssi_start_5g=int(self._ap_sta_info_5g['sta_rssi'].split('-')[0])	
	rssi_end_5g=int(self._ap_sta_info_5g['sta_rssi'].split('-')[1])
        rssi0_start_5g=int(self._ap_sta_info_5g['sta_mimorssi0'].split('-')[0])
        rssi0_end_5g=int(self._ap_sta_info_5g['sta_mimorssi0'].split('-')[1])
	rssi1_start_5g=int(self._ap_sta_info_5g['sta_mimorssi1'].split('-')[0])
	rssi1_end_5g=int(self._ap_sta_info_5g['sta_mimorssi1'].split('-')[1])
        
        rx_rate_list_5g=self._ap_sta_info_5g['sta_rx_rate'].split(',')
        rx_retry_list_5g=self._ap_sta_info_5g['sta_rx_retry'].split(',')
        
        tx_rate_list_5g=self._ap_sta_info_5g['sta_tx_rate'].split(',')
        tx_retry_list_5g=self._ap_sta_info_5g['sta_tx_retry'].split(',')
        tx_avarage_list_5g=self._ap_sta_info_5g['tx_avarage'].split(',')
	rx_avarage_list_5g=self._ap_sta_info_5g['rx_avarage'].split(',')
                    
	#print self._ap_list
        for ip in self._ap_list:

            copydata = copy.deepcopy(self._use_data)
        
            copydata['ap_g24_traffic']=self._ap_traffic
            copydata['ap_g5_traffic']=self._ap_traffic
        
            if copydata['ap_g24_sta_num'] != 'random':
               copydata['ap_g24_sta_num'] = int(copydata['ap_g24_sta_num'])
            else:
               copydata['ap_g24_sta_num']  = random.randint(0, 30)

            if copydata['ap_g5_sta_num'] != 'random':
                copydata['ap_g5_sta_num'] = int(copydata['ap_g5_sta_num'])
            else:
                copydata['ap_g5_sta_num']  = random.randint(0, 80)
            
            ap24_num = copydata['ap_g24_sta_num']/len(self._sta_item)
            ap5_num = copydata['ap_g5_sta_num']/len(self._sta_item)
            
            copydata['ap_mac'] = self._login_heart_list[ip]['ap_mac']

            copydata['ap_g24_sta_info']=[]
            copydata['ap_g5_sta_info']=[]
            
            for sta_mac in self._sta_item:
                start_mac = 0x1
                for v in range(0,ap24_num):       
                    stadata=copy.deepcopy(self._ap_sta_info)
                    stadata['sta_mac']=sta_mac[1] + self._switchhex(start_mac)
		    stadata['sta_rssi'] =random.randint(rssi_start,rssi_end)
                    stadata['sta_mimorssi0']  = random.randint(rssi0_start, rssi0_end)
	            stadata['sta_mimorssi1']  = random.randint(rssi1_start, rssi1_end)
                    stadata['sta_rx_rate']  = int(random.choice(rx_rate_list))
                    stadata['sta_rx_retry']  = int(random.choice(rx_retry_list))            
                    stadata['sta_tx_rate']  = int(random.choice(tx_rate_list))
                    stadata['sta_tx_retry']  = int(random.choice(tx_retry_list))
                    stadata['tx_avarage']  = int(random.choice(tx_avarage_list))
		    stadata['rx_avarage']  = int(random.choice(rx_avarage_list))
                    copydata['ap_g24_sta_info'].append(stadata)
                    start_mac = start_mac +1
                for v in range(0,ap5_num):
                    stadata=copy.deepcopy(self._ap_sta_info_5g)
                    
                    stadata['sta_mac']=sta_mac[1] + self._switchhex(start_mac)
                    stadata['sta_rssi']  = random.randint(rssi_start_5g, rssi_end_5g)
                    stadata['sta_mimorssi0']  = random.randint(rssi0_start_5g, rssi0_end_5g)
		    stadata['sta_mimorssi1']  = random.randint(rssi1_start_5g, rssi1_end_5g)
                    stadata['sta_rx_rate']  = int(random.choice(rx_rate_list_5g))
                    stadata['sta_rx_retry']  = int(random.choice(rx_retry_list_5g))            
                    stadata['sta_tx_rate']  = int(random.choice(tx_rate_list_5g))
                    stadata['sta_tx_retry']  = int(random.choice(tx_retry_list_5g))
                    stadata['tx_avarage']  = int(random.choice(tx_avarage_list_5g))
		    stadata['rx_avarage']  = int(random.choice(rx_avarage_list_5g))
                    copydata['ap_g5_sta_info'].append(stadata)
                    start_mac = start_mac +1
            self._user_info_list[ip] = copydata
        return self._user_info_list
    
class AP():
    
    _login_heart_request = {}
    _user_info_request={}
    _token='netcore'
    
    def __init__(self,server_ip,client_ip,login_heart_data,use_data):
        self._server_ip=server_ip
        self._client_ip=client_ip
        self._login_heart_request = login_heart_data
        self._user_info_request = use_data
        self._s_addr = (server_ip,20906)
        self.s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.s.setblocking(0)
        self.s.bind((client_ip,6720))
    
    def set_addr(self,server_ip):
        self._s_addr = (server_ip,20906)
        return self._s_addr
      
    def get_client_ip(self):
        return self._client_ip  
           
    def _request(self,Token,Token_len,Packet_type,Packet_length,Data):
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
        self.s.sendto(buf,self._s_addr)
    
    def request(self,status,timeout):
        self._request(self._token, -1, status, -1, self._login_heart_request)
        return self._recv(timeout,status)     
    
    def login_request(self,timeout):
        self._request(self._token, -1, AP_LOGIN_REQUEST, -1, self._login_heart_request)
        return self._recv(timeout,AP_LOGIN_REQUEST)
    
    def heart_request(self,timeout):
        self._request(self._token, -1, AP_HEART_REQUEST, -1, self._login_heart_request)
        return self._recv(timeout,AP_HEART_REQUEST)
        
    def user_request(self):
        self._request(self._token, -1, AP_USE_INFO, -1, self._user_info_request)
        
    def _recv(self,inter,status):
        infds,outfds,errfds = select.select([self.s],[],[],inter)
        if len(infds):
            r_data, addr = self.s.recvfrom(2048)
            if len(r_data):
                token, result_type,result_len= struct.unpack('!8sii' ,r_data[0:16])
                result = struct.unpack('!'+str(result_len)+'s' ,r_data[16:])
                if len(result):
                    self.set_addr(json.loads(result[0])['ac_ip'])
                return result_type
        else:
            if status == AP_LOGIN_REQUEST:
                status_s='login'
            elif status == AP_HEART_REQUEST:
                status_s='heart'
            else:
                status_s='error'
            print self._client_ip+ "  "   + status_s +" timeout!!!"
            logging.debug(self._client_ip+ "  "   + status_s +" timeout!!!")
            return False
            
    def close(self):
        self.s.close()
 
    
def mock_ap(ap):
    
    global is_exit
    num = 0
    overtime = 3
    inter_time = mockconfig.getHeartTime()
    status=AP_LOGIN_REQUEST
    while not is_exit:
        time.sleep(1)
        result=ap.request(status, mockconfig.getWaitTime())
        if result !=False:
            if hex(result)== hex(AP_LOGIN_REPLY):
                status=AP_HEART_REQUEST
            elif hex(result)==hex(AP_HEART_REPLY):
                pass
            
            ap.user_request()
            time.sleep(inter_time)
        else:
            print ap.get_client_ip()+" timeout " + str(num) 
            num=num+1
            if num < overtime:
                continue
            else:
                num=0            
            ap.set_addr(mockconfig.getBroadcast())
            status=AP_LOGIN_REQUEST
        
    mockconfig.DeleteIp(ap.get_client_ip())
    time.sleep(0.1)
    ap.close()
    
class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def _writeheaders(self):
        #print self.path
        #print self.headers
        self.protocol_version = 'HTTP/1.1'
        self.send_response(200);
        self.send_header('Content-type','text/html');
        self.end_headers()
    def do_Head(self):
        self._writeheaders()
    def do_GET(self):
        self._writeheaders()
        self.wfile.write(mockconfig.getCgiResponse())
    def do_POST(self):
        #form=cgi.FieldStorage()
        #time.sleep(2)
        data = self.rfile.read(int(self.headers['content-length']))
        print data
        self._writeheaders()
        self.wfile.write(mockconfig.getCgiResponse())

def start_web(ip):
    server_class=BaseHTTPServer.HTTPServer
    handler_class=RequestHandler
    server_address = (ip, 80)
    httpd = server_class(server_address, handler_class)
    httpd.allow_reuse_address=True
    httpd.serve_forever()
     
        
if __name__ == "__main__" :
    
    logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='run.log',
                filemode='w')
    
    
    mockconfig=ConfigSystem('config.txt')
    
    signal.signal(signal.SIGINT, signal_init)
    signal.signal(signal.SIGTERM,  signal_init)
    
    mockconfig.ConfigIp()
    loginheart_list=mockconfig.GetloginHeartList()
    userInfo_list=mockconfig.GetUserInfoList()
    
    for ip in mockconfig.getIpList():
        time.sleep(mockconfig.getIntertime())  
        ap=AP(mockconfig.getBroadcast(),ip,loginheart_list[ip],userInfo_list[ip])
        #print mockconfig.GetUserInfoList()[ip]['ap_mac']
        try:
            #print ap
            action_thread = threading.Thread(target=mock_ap,args=(ap,))
            action_thread.setDaemon(True)
            action_thread.start()
            Theads.append(action_thread)
        except (KeyboardInterrupt,SystemExit):
                raise
        except:
                traceback.print_exc()
        
	if mockconfig.getEnable()==1:
            p = multiprocessing.Process(target=start_web, args=(ip,)) 
            p.start()
            web_list.append(p)
    
    print "虚拟AP已经启动, AC地址务必在广播网段的50以内，Cril + C 停止运行"
    while True:
        alive = False
        for T in Theads:
            alive = alive or T.isAlive()
        if not alive:
            break
    if mockconfig.getEnable()==1:
        os.system('killall -9 /usr/bin/python')
    
    

        
    
