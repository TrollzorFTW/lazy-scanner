# Lazy Scanner

## Purpose
	Incorporates nmap and ffuf in one tiny CLI app with easier syntax to make life bearable for people that hate Recon phase(including myself).

## Usage
```
lazy_scanner.py [-h] 
--target TARGET 
--tool TOOL 
[--wordlist WORDLIST] 
[--method METHOD] 
[--additional ADDITIONAL]
```
```
optional arguments:
  -h, --help            show this help message and exit
  
  --target TARGET       target that will be scanned
  
  --tool TOOL           scan tool (nmap,ffuf)
  
  --wordlist WORDLIST   wordlist for ffuf
  
  --method METHOD       scan method for ffuf (subdomain,directory)
  
  --additional ADDITIONAL
                        additional arguments for ffuf (example: -fc 403 -fl 20 etc.)
```

## Examples
`Nmap scan`
```
./lazy_scanner.py --target [target-ip/dns] --tool nmap
```

`Directory scan`
```
./lazy_scanner.py \
--target https://target.here \
--tool ffuf \
--wordlist ~/tools/SecLists/Discovery/Web-Content/big.txt \
--method directory
```

`Subdomain scan`
```
./lazy_scanner.py \
--target http://target.here \
--tool ffuf \
--wordlist ~/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
--method subdomain \
--additional '-fc 403'
```