# pam_sqlite3


## create pam service 
    /etc/pam.d/openvpn
    auth        required    pam_sqlite3.so db=/etc/openvpn/openvpn.db table=openvpn usercolumn=username passwdcolumn=password active=1 expiredcolumn=enddate logincolumn=logintime logoutcolumn=logouttime crypt=1
    account     required    pam_sqlite3.so db=/etc/openvpn/openvpn.db table=openvpn usercolumn=username passwdcolumn=password active=1 expiredcolumn=enddate logincolumn=logintime logoutcolumn=logouttime crypt=1
 crypt: <br />
 0 = No encryption <br />
 1 = md5 <br />
 2 = sha1 <br />

## create sqlite3 file
    /etc/openvpn/openvpn.db
    create table openvpn(
         username text not null, 
         password text not null, 
         active int, 
         enddate text, 
         logintime text,
         logouttime text, -- Not yet implemented
         remote text
    );

## Run command cmd(or script) when the client connects or disconnects.
    /etc/openvpn/server/server.conf
    script-security 2
    client-connect /etc/openvpn/connect.py
    client-disconnect /etc/openvpn/disconnect.py

disconnect.py <br />
    \#!/usr/bin/python

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
