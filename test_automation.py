import requests
import logging
from scapy.all import *
import threading
import json
import time
from typing import Optional
from queue import Queue

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NotificationCapture:
    """使用scapy捕获通知请求和响应"""
    def __init__(self):
        self.notification_queue = Queue()
        self.stop_capture = threading.Event()
        self.request_received = False
        self.response_received = False
        
    def packet_callback(self, packet):
        """处理捕获的数据包，解析HTTP请求和响应"""
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                # 获取源地址和目标地址
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload = packet[Raw].load.decode('utf-8')
                
                # 处理请求（发往18080端口的包）
                if packet[TCP].dport == 18080 and 'POST /notifications' in payload:
                    self.request_received = True
                    logger.info("\n=== 捕获到通知请求 ===")
                    logger.info(f"源地址: {src_ip}:{src_port}")
                    logger.info(f"目标地址: {dst_ip}:{dst_port}")
                    
                    # 解析HTTP请求头和请求体
                    headers = {}
                    body = ""
                    
                    parts = payload.split('\r\n\r\n')
                    header_section = parts[0]
                    if len(parts) > 1:
                        body = parts[1]
                        
                    header_lines = header_section.split('\r\n')
                    request_line = header_lines[0]
                    logger.info(f"请求行: {request_line}")
                    
                    for line in header_lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            headers[key] = value
                            logger.info(f"请求头: {key}: {value}")
                    
                
                # 处理响应（来自18080端口的包）
                elif self.request_received and packet[TCP].sport == 18080 and 'HTTP/' in payload:
                    self.response_received = True
                    logger.info("\n=== 捕获到通知响应 ===")
                    logger.info(f"源地址: {src_ip}:{src_port}")
                    logger.info(f"目标地址: {dst_ip}:{dst_port}")
                    
                    # 解析HTTP响应
                    parts = payload.split('\r\n\r\n')
                    header_section = parts[0]
                    
                    header_lines = header_section.split('\r\n')
                    status_line = header_lines[0]
                    logger.info(f"状态行: {status_line}")
                    
                    # 解析响应头
                    response_headers = {}
                    for line in header_lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            response_headers[key] = value
                            logger.info(f"响应头: {key}: {value}")
                    
                    # 如果有响应体，则打印
                    if len(parts) > 1:
                        response_body = parts[1]
                        logger.info("响应体:")
                        try:
                            body_json = json.loads(response_body)
                            logger.info(json.dumps(body_json, indent=2, ensure_ascii=False))
                        except json.JSONDecodeError:
                            logger.info(response_body)
                    
                    # 收到响应后，通知主线程可以结束了
                    self.notification_queue.put({
                        'status': 'complete',
                        'message': '已捕获请求和响应'
                    })
                    
            except Exception as e:
                logger.error(f"解析数据包时出错: {str(e)}")

    def start_capture(self):
        """开始捕获数据包"""
        # 修改过滤器以同时捕获请求和响应
        capture_filter = (
            f"tcp and host 27.148.193.68 and ("
            f"(dst port 18080) or "  # 捕获发往18080的请求
            f"(src port 18080)"      # 捕获来自18080的响应
            f")"
        )
        logger.info("开始捕获网络流量...")
        logger.info(f"使用过滤器: {capture_filter}")
        
        # 在新线程中启动数据包捕获
        sniff_thread = threading.Thread(
            target=lambda: sniff(
                filter=capture_filter,
                prn=self.packet_callback,
                stop_filter=lambda _: self.stop_capture.is_set()
            )
        )
        sniff_thread.daemon = True
        sniff_thread.start()
        return sniff_thread

class LogisticsAPIClient:
    """物流API客户端"""
    def __init__(self, auth_url: str, api_base_url: str):
        self.auth_url = auth_url
        self.api_base_url = api_base_url
        self.token: Optional[str] = None
        
    def get_token(self) -> str:
        """获取认证token"""
        auth_data = {
            'grant_type': 'client_credentials',
            'client_id': 'neone-client',
            'client_secret': 'lx7ThS5aYggdsMm42BP3wMrVqKm9WpNY'
        }
        response = requests.post(self.auth_url, data=auth_data)
        response.raise_for_status()
        self.token = response.json()['access_token']
        logger.info("✓ Token获取成功")
        return self.token

    def test_connection(self):
        """测试服务器连接"""
        response = requests.get(
            f"{self.api_base_url}/",
            headers=self._get_headers()
        )
        response.raise_for_status()
        logger.info("✓ 服务器连接测试成功")

    def create_subscription(self, callback_url: str):
        """创建订阅"""
        print(callback_url)
        payload = {
            "@context": {
                "cargo": "https://onerecord.iata.org/ns/cargo#",
                "api": "https://onerecord.iata.org/ns/api#"
            },
            "@type": "api:Subscription",
            "api:hasContentType": "application/ld+json",
            "api:hasSubscriber": {"@id": callback_url},
            "api:hasTopicType": {"@id": "api:LOGISTICS_OBJECT_TYPE"},
            "api:includeSubscriptionEventType": [
                {"@id": "api:LOGISTICS_OBJECT_UPDATED"},
                {"@id": "api:LOGISTICS_OBJECT_CREATED"},
                {"@id": "api:LOGISTICS_EVENT_RECEIVED"}
            ],
            "api:hasTopic": {"@id": "cargo:test1"}
        }
        
        response = requests.post(
            f"{self.api_base_url}/subscriptions",
            headers=self._get_headers(),
            json=payload
        )
        response.raise_for_status()
        logger.info("✓ 订阅创建成功")

    def create_logistics_object(self):
        """创建物流对象"""
        payload = {
            "@context": {"cargo": "https://onerecord.iata.org/ns/cargo#"},
            "@type": ["cargo:test1", "cargo:LogisticsObject"],
            "cargo:name": "IATA",
            "cargo:shortName": "IATA",
            "cargo:contactPersons": [{
                "@type": ["cargo:Person", "cargo:Actor", "cargo:LogisticsAgent", "cargo:LogisticsObject"],
                "cargo:firstName": "Jackie",
                "cargo:lastName": "ZUO",
                "cargo:salutation": "Mr"
            }]
        }
        
        response = requests.post(
            f"{self.api_base_url}/logistics-objects?public=true",
            headers=self._get_headers(),
            json=payload
        )
        response.raise_for_status()
        logger.info("✓ 物流对象创建成功")

    def _get_headers(self):
        """获取请求头"""
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/ld+json'
        }

def main():
    # 配置
    AUTH_URL = "http://52.80.236.181:8989/realms/neone/protocol/openid-connect/token"
    API_BASE_URL = "http://localhost:8080"
    CALLBACK_URL = "http://27.148.193.68:18080"
    
    try:
        # 创建并启动数据包捕获器
        capture = NotificationCapture()
        capture_thread = capture.start_capture()
        
        # 创建API客户端并执行测试步骤
        client = LogisticsAPIClient(AUTH_URL, API_BASE_URL)
        
        # 执行测试步骤
        client.get_token()#获取token
        client.test_connection()#测试是否能Get对方服务器
        client.create_subscription(CALLBACK_URL)#发起订阅
        client.create_logistics_object()#创建物流对象
        
        # 等待捕获通知和响应
        timeout = 90
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            try:
                result = capture.notification_queue.get(timeout=1)
                if result.get('status') == 'complete':
                    logger.info(result['message'])
                    break
            except queue.Empty:
                if int(time.time() - start_time) % 10 == 0:
                    logger.info("等待通知中...")
        
        if (time.time() - start_time) >= timeout:
            logger.warning("⚠ 等待通知超时")
            
    except Exception as e:
        logger.error(f"程序执行出错: {str(e)}")
    finally:
        # 停止捕获
        capture.stop_capture.set()
        capture_thread.join(timeout=2)

if __name__ == "__main__":
    main()