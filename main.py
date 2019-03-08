#!/usr/bin/env python3

import nmap
from ssh_user_enumeration import main

host = "127.0.0.1"
vulnerable_ssh_version = "7.9"

nm = nmap.PortScanner()
nm.scan(hosts=host, arguments=' -f --mtu 24 --open -n -Pn -sV')

try:
  nmap_result = nm[host]["tcp"]
  nmap_result_info = dict()
  nmap_result_ssh_version = str()


  for key, value in nmap_result.items():
    if key == 22:
      nmap_result_info = value
      for key, value in nmap_result_info.items():
        if value == "ssh":
          nmap_result_ssh_version = nmap_result_info["version"]
          break

  if nmap_result_ssh_version < vulnerable_ssh_version:
    main(host, 22)
except KeyError as ke:
  pass
