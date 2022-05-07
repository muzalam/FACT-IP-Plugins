from ipaddress import ip_address
from dns import resolver
import whois
import requests
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'Virustotal_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	MIME_WHITELIST = ['text/plain', 'application/octet-stream', 'application/x-executable', 'application/x-object','application/x-sharedlib', 'application/x-dosexec']
	DESCRIPTION = (
	'Returns the results of API query to VirusTotal for all extraced IPs. API key required.'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):

		self.api_key = "898e54e360cdf32b5714e2d14d3881d6c0274f21a791d972244a4ebe86b2e711"

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
				data = self.get_domains_from_uri(data)
				final_data[data] = {}
				domains_to_ips = self.get_ips_from_domain(data)
				for ip in domains_to_ips:
					final_data[data][f'VirusTotal {data} to_ip: {ip}'] = self.virustotalIp([ip])

			else:
				final_data[data] = {}
				final_data[data]['VirusTotalIP'] = self.virustotalIp([data])


		file_object.processed_analysis[self.NAME] = final_data
		return file_object
	
	def is_ip(self,data):
		try:
			ip_address(data)
			return True
		except:
			return False

			
	# IP Part using VirusTotal
	def virustotalIp(self,IP):
		return_dict = {}
		try:
			for ip in IP:
				header={ "X-Apikey": self.api_key}
				url="https://www.virustotal.com/api/v3/ip_addresses/" + ip
				response_ip_rep=requests.get(url, headers=header)

				if(response_ip_rep.status_code==200):
					ip_rep=response_ip_rep.json()
					#print(ip_rep)

					return_dict = {'harmless':str(ip_rep['data']['attributes']['last_analysis_stats']['harmless']),'malicious':str(ip_rep['data']['attributes']['last_analysis_stats']['malicious']),'suspicious':(str(ip_rep['data']['attributes']['last_analysis_stats']['suspicious'])),'undetected':str(ip_rep['data']['attributes']['last_analysis_stats']['undetected'])}
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






