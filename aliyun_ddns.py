# -*- coding: utf-8 -*-

import os
import uuid
import json
import requests
import re
from datetime import datetime
import urllib
import hmac
import base64


REQUEST_URL = 'https://alidns.aliyuncs.com/'
IP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ip.txt')
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

with open(CONFIG_FILE, 'r') as f:
	settings = json.loads(f.read())

def get_common_params(settings):
	"""
	获取公共参数
	参考文档：https://help.aliyun.com/document_detail/29745.html?spm=5176.doc29776.6.588.sYhLJ0
	"""
	return {
		'Format': 'json',
		'Version': '2015-01-09',
		'SignatureMethod': 'HMAC-SHA1',
		'SignatureNonce': uuid.uuid4(),
		'SignatureVersion': '1.0',
		'AccessKeyId': settings['access_key'],
		'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
	}


def get_signed_params(http_method, params, settings):
	"""
	参数加入签名
	参考文档：https://help.aliyun.com/document_detail/29747.html?spm=5176.doc29745.2.1.V2tmbU
	"""
	# 1、合并设置文件中的参数，不包括Signature
	params.update(get_common_params(settings))
	# 2、按照参数名称的字典顺序进行排序
	sorted_params = sorted(params.items())
	# 3、对合并排序后的参数进行urlencode编码，得到的是多个key=value的键值对通过&符号连接后组成的字符串
	query_params = urllib.parse.urlencode(sorted_params)
	# 4、再处理一次，将urlencode后的字符串中的“=”和“&”进行percent编码
	urlencode_params = urllib.parse.quote_plus(query_params)
	# 5、构造需要签名的字符串
	str_to_sign = http_method + "&" + urllib.parse.quote_plus("/") + "&" + urlencode_params
	# 6、计算签名
	h = hmac.new((settings['access_secret']+"&").encode(), str_to_sign.encode(), digestmod="sha1")
	signature = base64.b64encode(h.digest()).strip().decode()
	# print("[signature]", signature)
	# 7、将签名加入参数中
	params['Signature'] = signature
	return params

def update_aliddns(ip):
	"""
	修改云解析
	参考文档：
		获取解析记录：https://help.aliyun.com/document_detail/29776.html?spm=5176.doc29774.6.618.fkB0qE
		修改解析记录：https://help.aliyun.com/document_detail/29774.html?spm=5176.doc29774.6.616.qFehCg
	"""
	# 首先获取解析列表
	get_params = get_signed_params('GET', {
		'Action': 'DescribeDomainRecords',
		'DomainName': settings['domain'],
		'TypeKeyWord': 'A'
	}, settings)

	get_resp = requests.get(REQUEST_URL, get_params)
	records = get_resp.json()
	print('============ get_records ============')
	print(records)

	if 'DomainRecords' in records:
		update_sign = False
		for record in records['DomainRecords']['Record']:
			if settings['hostname'] == record['RR']:
				post_params = get_signed_params('POST', {
					'Action': 'UpdateDomainRecord',
					'RecordId': record['RecordId'],
					'RR': settings['hostname'],
					'Type': record['Type'],
					'Value': ip
				}, settings)
				post_resp = requests.post(REQUEST_URL, post_params)
				result = post_resp.json()
				print('============ update_record ============')
				print(result)
				update_sign = True
				print("update remote record Success ！！！")
		if not update_sign:
			print("hostname is not in DomainRecords ！！！")
	else:
		print("something is wrong ！！！")

		
def get_curr_ip():
	# return "1.2.3.4"
	resp = requests.get('http://jsonip.com')
	if resp.status_code == 200:
		ip = json.loads(resp.text)['ip']
		return ip
	return None
	

def get_lastest_local_ip():
	"""
	获取最近一次保存在本地的ip
	"""
	with open(IP_FILE, 'a+') as f:
		f.seek(0)
		ip_list = f.readlines()
		if ip_list:
			last_ip = ip_list[-1].strip()
			return last_ip
		return

if __name__ == '__main__':
	ip = get_curr_ip()
	if not ip:
		print('get ip failed !!!')
	else:
		last_ip = get_lastest_local_ip()
		print(f"<{ip}>", f"<{last_ip}>")
		if ip != last_ip:
			print(f'save ip to {IP_FILE}')
			with open(IP_FILE, 'a') as f:
				f.write(ip+"\n")
			print('update remote record...')
			update_aliddns(ip)
		else:
			print('ip have not changed')
