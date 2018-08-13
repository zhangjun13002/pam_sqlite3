#!/usr/bin/python

import os
import time
import sqlite3

clientname = os.environ['common_name']
clientip = os.environ['trusted_ip']
logouttime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))

conn = sqlite3.connect("/etc/openvpn/openvpn.db")
query = "update openvpn set logouttime='%s', remote='%s' where username='%s'" % (logouttime, clientip, clientname)
conn.execute(query)
conn.commit()
conn.close()

