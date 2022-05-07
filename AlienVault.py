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
	NAME = 'AlienVault_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	MIME_WHITELIST = ['text/plain', 'application/octet-stream', 'application/x-executable', 'application/x-object','application/x-sharedlib', 'application/x-dosexec']
	DESCRIPTION = (
	'Returns the results of API queries to AlienVault 3rd party data source. No API key required.'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):

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
				final_data[data]['AlienVaultDomain'] = self.alienDomain([data])
				domains_to_ips = self.get_ips_from_domain(data)
				for ip in domains_to_ips:
					final_data[data][f'AlienVault {data} to_ip: {ip}'] = self.alienvaultIp([ip])

			else:
				final_data[data] = {}
				final_data[data]['AlienVaultIP'] = self.alienvaultIp([data])
				ips_to_domains = self.get_domains_from_ip(data)
				for domain in ips_to_domains:
					final_data[data][f'AlienValut {data} to_domain: {domain}'] = self.alienDomain([domain])
		file_object.processed_analysis[self.NAME] = final_data
		return file_object
	
	def is_ip(self,data):
		try:
			ip_address(data)
			return True
		except:
			return False
			
	#IP Part using ALienVault
	def alienvaultIp(self, IP):
		return_dict= {}
		try:
			for ip in IP:
				url_ip="https://otx.alienvault.com/api/v1/indicators/IPv4/"+ip+"/geo"
				response=requests.get(url_ip)

				if(response.status_code==200):
					geo_dict=response.json()
					return_dict = {"asn":geo_dict['asn'],'continent':geo_dict['continent_code'],'latitude':geo_dict['latitude'],'longitude':geo_dict['longitude'],'country':geo_dict['country_name']}
					return(pprint.pformat(return_dict))

				else:
					return "No data found, or asset is not a web host"
		except Exception as e:
			return "No data found, or asset is not a web host"

		
	def alienDomain(self, Domains):
		try:
			for domain in Domains:
				url_domain= "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/geo"
				response_domain=requests.get(url_domain)

				if(response_domain.status_code==200):
					geo_dict=response_domain.json()
					return_dict = {'asn':geo_dict['asn'],'continent':geo_dict['continent_code'],'latitude':str(geo_dict['latitude']),'longitude':str(geo_dict['longitude']),'country':geo_dict['country_name']}
					""" print("\nAnalyzing the Domains via various sources......\n")
					print("\nDomain Name being Analyzed: " + str(domain) + "\n")
					print("ASN: " + geo_dict['asn'])
					print("Continent: " + geo_dict['continent_code'])
					print("Latitude: " + str(geo_dict['latitude']) + " and Longitude: " + str(geo_dict['longitude']))
					print("Country: " + geo_dict['country_name']) """
					return(pprint.pformat(return_dict))

				else:
					return{"Response_Status":str(response_domain.status_code)}
		except Exception as e:
			return {"AlienVault Error":f"ERROR: {Domains}"}
	

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
	



