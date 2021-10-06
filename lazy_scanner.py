#!/usr/bin/python3
import subprocess
import argparse
import nmap
import re


def execute_command(cmd):
	subprocess.run(cmd,shell=True)

def beautify_string(info):
	service_name = info['name']
	service_product = info['product']
	service_version = info['version']
	beautified_string = "Service {} {}, Version: {}".format(service_name,service_product,service_version)

	return beautified_string


def scan_nmap(target):
	
	print("\n\nScanning for open ports on target {}...".format(target))
	
	nm = nmap.PortScanner()
	result = nm.scan(target,arguments='-p-')

	ip = list(result['scan'].keys())[0]
	ports = list(result['scan'][ip]['tcp'].keys())
	ports_string = ','.join(str(p) for p in ports)
	print("\n[*]Open ports {}".format(ports_string))

	answer = input("Do you wish to scan further on these ports? (service/version info) [Y/n]: ") or 'Y'

	if answer.upper() == 'Y':
		output_flag = input("Do you wish to output the results to a file? (more verbose) [Y/n]: ") or 'Y'
		if output_flag.upper() == 'Y':
			output_path = input("Specify the path for output(including filename): ")
			result = nm.scan(target,arguments='-p{} -sV -oN {}'.format(ports_string,output_path))
		else:
			result = nm.scan(target,arguments='-p{} -sV'.format(ports_string))

		ports_info = result['scan'][ip]['tcp']
		for port in ports:
			info = beautify_string(ports_info[port])
			print("\nPort {}\n{}".format(port,info))
			
	else:
		return


def scan_ffuf(target,method,wordlist,additional_arguments):
	
	print("\nFFuF scan initializing...\n")
	output_flag = input("Do you wish to output the results to a file? [Y/n]: ") or 'Y'
	if output_flag.upper() == 'Y':
		output_path = input("Specify the path for output(including filename): ")

	if not output_path:
		output_flag = 'N'

	if method == 'directory':
		print("Directory scan starting on target {}".format(target))
		if additional_arguments:
			if output_flag == 'Y':
				cmd = 'ffuf -w {} -u {}/FUZZ {} | tee {}'.format(wordlist,target,additional_arguments,output_path)
			else:
				cmd = 'ffuf -w {} -u {}/FUZZ {}'.format(wordlist,target,additional_arguments)
		else:
			if output_flag == 'Y':
				cmd = 'ffuf -w {} -u {}/FUZZ | tee {}'.format(wordlist,target,output_path)
			else:
				cmd = 'ffuf -w {} -u {}/FUZZ'.format(wordlist,target)
	else:
		print("Subdomain scan starting on target {}".format(target))
		main_host = "Host: FUZZ.{}".format(target.split('://')[1])
		if additional_arguments:
			if output_flag == 'Y':
				cmd = 'ffuf -w {} -u {} -H "{}" {} | tee {}'.format(wordlist,target,main_host,additional_arguments,output_path)
			else:
				cmd = 'ffuf -w {} -u {} -H "{}" {}'.format(wordlist,target,main_host,additional_arguments)
		else:
			if output_flag == 'Y':
				cmd = 'ffuf -w {} -u {} -H "{}" | tee {}'.format(wordlist,target,main_host,output_path)
			else:
				cmd = 'ffuf -w {} -u {} -H "{}"'.format(wordlist,target,main_host)

	execute_command(cmd)


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument('--target',type=str,help='target that will be scanned',required=True)
	parser.add_argument('--tool',type=str,help='scan tool (nmap,ffuf)',required=True)
	parser.add_argument('--wordlist',type=str,help='wordlist for ffuf')
	parser.add_argument('--method',type=str,help='scan method for ffuf (subdomain,directory)')
	parser.add_argument('--additional',type=str,help='additional arguments for ffuf (example: -fc 403 -fl 20 etc.)')

	args = parser.parse_args()
	
	if args.tool == 'nmap':
		scan_nmap(args.target)
	elif args.tool == 'ffuf':
		if (args.wordlist is None or args.method is None):
			parser.error("--wordlist and --method arguments required for ffuf")
		elif args.method not in ['subdomain','directory']:
			parser.error("Invalid method {}. Available methods: subdomain,directory".format(args.method))
		else:

			if not (args.target.startswith('http://') or args.target.startswith('https://')):
				print("Target has to be an URL")
				return
			scan_ffuf(args.target,args.method,args.wordlist,args.additional)

	else:
		parser.error("Invalid tool {}. Available tools: nmap,ffuf".format(args.tool))


if __name__ == '__main__':
	main()
