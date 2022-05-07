from ipaddress import ip_address
from dns import resolver
import whois
import requests
import time, pprint, datetime
from requests.auth import HTTPBasicAuth
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'XForce_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	MIME_WHITELIST = ['text/plain', 'application/octet-stream', 'application/x-executable', 'application/x-object','application/x-sharedlib', 'application/x-dosexec']
	DESCRIPTION = (
	'Returns the results of API query to XForce for all extracted Domains and IPs. API key required.'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.key1 = '596dda3c-5763-46f4-a8a0-82b6c27bdb75'
		self.key2 = 'd83c4aef-fc33-4f6d-874a-61d3a7574735'

		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
		super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

	def process_object(self, file_object):
		final_data = {} #dict of original artifact mapped to analysis
		#result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		result = file_object.processed_analysis['ip_and_uri_finder']['summary']
		for data in result:
			if type(data) != str:
				continue
			final_data[data] = {}
			if not self.is_ip(data):
				final_data[data]['XForceURI'] = self.xforceDomain(data)
				
				data = self.get_domains_from_uri(data)
				final_data[data] = {}
				final_data[data]['XForceDomain'] = self.xforceDomain(data)
				domains_to_ips = self.get_ips_from_domain(data)
				for ip in domains_to_ips:
					final_data[data][f'XForce {data} to_ip: {ip}'] = self.xforceIp(ip)

			else:

				final_data[data]['XForceIP'] = self.xforceIp(data)
				ips_to_domains = self.get_domains_from_ip(data)
				for domain in ips_to_domains:
					final_data[data][f'Xforce {data} to_domain: {domain}'] = self.xforceDomain(domain)

		file_object.processed_analysis[self.NAME] = final_data
		return file_object
	
	def is_ip(self,data):
		try:
			ip_address(data)
			return True
		except:
			return False


	# Domain/URL Part using X-Force 
	# This part below can also analyze the URLs along with the domain names
	def xforceDomain(self, domain):
		try:
			url_ip_history="https://api.xforce.ibmcloud.com/api/url/" + domain
			auth = HTTPBasicAuth(self.key1, self.key2)
			response = requests.get(url_ip_history, auth = auth)

			if(response.status_code==200):
				data_url=response.json()
				return_dict={'domain_category':str(data_url['result']['cats']),'threat_score':str(data_url['result']['score']),'description':str(data_url['result']['categoryDescriptions']['Search Engines / Web Catalogues / Portals'])}

				return(pprint.pformat(return_dict))
			else:
				return "No data found, or asset is not a web host"
		except Exception as e:
			return "No data found, or asset is not a web host"

	# IP Part Using X-Force
	def xforceIp(self, ip):
		try:
			url_ip_history="https://api.xforce.ibmcloud.com/api/ipr/history/" + ip
			auth = HTTPBasicAuth(self.key1, self.key2)
			response = requests.get(url_ip_history, auth = auth)

			if(response.status_code==200):
				resp_ip_history=response.json()
				l=len(resp_ip_history['history'])

				for i in range(l):
					return_dict = {'date_of_record':str(resp_ip_history['history'][i]['created']),'location':str(resp_ip_history['history'][i]['geo']['country']),'category':str(resp_ip_history['history'][i]['categoryDescriptions']),'description':str(resp_ip_history['history'][i]['reasonDescription']),'threat_score':str(resp_ip_history['history'][i]['score'])}

				return(pprint.pformat(return_dict))

			else:
				return "No data found, or asset is not a web host"
		except Exception as e:
			return "No data found, or asset is not a web host"

			
	def get_domains_from_uri(self, uri):
		sub_strs = uri.split("://")
		if len(sub_strs) == 1: #case where no protocol
			domain = (sub_strs[0])
		else:
			domain = (sub_strs[1].split("/")[0])
		return domain
		

	def get_ips_from_domain(self, domain):
		try:
			ips = []
			response = resolver.resolve(domain,'A')
			for ip in response:
				ips.append(str(ip))
			return ips
		except:
			return [f'Error resolving {domain}']
	def get_domains_from_ip(self, ip):
		try:
			domains = []
			response = resolver.resolve_address(ip)
			for domain in response:
				domains.append(str(domain))
			return domains
		except Exception as e:
			return [f'No DNS records found {ip}']
	
	
	def remove_duplicates(self, input_list):
		return list(set(input_list))
	



