#! /usr/bin/env python

#    This is saegw.py - SAE gateway
#    Version 0.1
#    Copyright (C) 2010 Grzegorz Pawelski <grzegorz.pawelski@nsn.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


############################# CONFIG ################################### 

sgw_ip_s11 = "192.168.18.200"	#local address S11
sgw_ip_s1 = "192.168.18.200"	#local address S1U
pgw_ip = "192.168.18.200"	#PDN-GW address
mme_ip = "192.168.17.128"	#remote address S11
enodeb_ip = "192.168.19.100"	#remote address S1U
sae_prfx = "10.88.46.0/24"	#addresses for mobiles - must be /24
dscp = 0x00			#DSCP for GTP-U pkts

########################################################################



import struct, socket, threading, time, select, curses, fcntl, os, sys, string
from gtpv2 import *


sae_prfx = sae_prfx[0:string.rfind(sae_prfx,'.')+1]
current_ip = 1
interval = 2

tab = {}
tab[0] = [0, 0, "0.0.0.0", 0, 0]     #key local teid: [current_ip, local teid, pdn ip, remote teid S11, remote teid S1U]
recv = 0
acked = 0

ip_tab = {}
for i in range(0, 256):
    ip_tab[i] = 0x10000000+i

sockc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockc.setblocking(True)
sockc.bind((sgw_ip_s11, 2123))

socku = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socku.setblocking(True)
socku.bind((sgw_ip_s1, 2152))

f = open('out.txt','w')

m_cre_req = GTP_CREATE_SESS_REQ()
m_cre_res = GTP_CREATE_SESS_RES()
m_mod_req = GTP_MODIFY_BEAR_REQ()
m_mod_res = GTP_MODIFY_BEAR_RES()
m_del_req = GTP_DELETE_SESS_REQ()
m_del_res = GTP_DELETE_SESS_RES()
m_rel_req = GTP_RELEAS_BEAR_REQ()
m_rel_res = GTP_RELEAS_BEAR_RES()


def setup_gtpu(ip, teid):
    fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETSAEIP, struct.pack('16sI', "gtp0", ip))
    fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETSAETEID, struct.pack('16sI', "gtp0", teid))


def receiver(buff):
    global current_ip
    head_in = GTP_HEAD()
    head_in.dec(buff[0:12])
    if head_in.version == 2 and head_in.type == CREATE_SESS_REQ:
         m_cre_req.dec(buff)
         m_cre_res.cause.enc(CAUSE_REQ_ACCEPTED, 0)
         m_cre_res.f_teid.enc(TEID_SGW, ip_tab[current_ip], sgw_ip_s11)
         m_cre_res.f_teid1.enc(TEID_S5PGW, ip_tab[current_ip], pgw_ip)
         pdn_addr = "%s%i" % (sae_prfx,current_ip)
         m_cre_res.pdn_addr.enc(pdn_addr)
         m_cre_res.apn_restr.enc(0)
         m_cre_res.pco.enc('8080210a0100000a810600000000')       
         m_cre_res.bearer_ctxt.ebi.enc(5)
         m_cre_res.bearer_ctxt.cause.enc(CAUSE_REQ_ACCEPTED, 0)
         m_cre_res.bearer_ctxt.f_teid.enc(TEID_SGWU, ip_tab[current_ip], sgw_ip_s1)
         m_cre_res.bearer_ctxt.enc()
         if m_cre_req.f_teid.typ == TEID_MME:
             teid_mme = m_cre_req.f_teid.teid
         elif m_cre_req.f_teid1.typ == TEID_MME:
             teid_mme = m_cre_req.f_teid1.teid
         m_cre_res.enc(teid_mme,head_in.seq,head_in.spare)
         tab[ip_tab[current_ip]] = [current_ip, ip_tab[current_ip], pdn_addr, teid_mme, 0]
         current_ip = current_ip + 1
         sockc.sendto(m_cre_res.out, (mme_ip, 2123))
    elif head_in.version == 2 and head_in.type == MODIFY_BEAR_REQ: 
         m_mod_req.dec(buff)
         m_mod_res.cause.enc(CAUSE_REQ_ACCEPTED, 0)
         m_mod_res.bearer_ctxt.ebi.enc(5)
         m_mod_res.bearer_ctxt.cause.enc(CAUSE_REQ_ACCEPTED, 0)
         m_mod_res.bearer_ctxt.f_teid.enc(TEID_SGWU, head_in.teid, sgw_ip_s1)
         m_mod_res.bearer_ctxt.enc()
         m_mod_res.enc(tab[head_in.teid][3],head_in.seq,head_in.spare)
         tab[head_in.teid][4] = m_mod_req.bearer_ctxt.f_teid.teid
         setup_gtpu(tab[head_in.teid][0], m_mod_req.bearer_ctxt.f_teid.teid)    
         sockc.sendto(m_mod_res.out, (mme_ip, 2123))
    elif head_in.version == 2 and head_in.type == DELETE_SESS_REQ:
         m_del_req.dec(buff)
         m_del_res.cause.enc(CAUSE_REQ_ACCEPTED, 0)
         m_del_res.enc(tab[head_in.teid][3],head_in.seq,head_in.spare)
         sockc.sendto(m_del_res.out, (mme_ip, 2123))
    elif head_in.version == 2 and head_in.type == ECHO_REQ:
         sequen = buff[4:8]
         gtpv2_resp = "\x40\x02\x00\x09"+sequen+"\x03\x00\x01\x00\x01"
         sockc.sendto(gtpv2_resp, (sgw_ip_s11, 2123))
    elif head_in.version == 2 and head_in.type == RELEAS_BEAR_REQ:
         m_rel_req.dec(buff)
         m_rel_res.cause.enc(CAUSE_REQ_ACCEPTED, 0)
         m_rel_res.enc(tab[head_in.teid][3],0,head_in.spare)
         sockc.sendto(m_rel_res.out, (mme_ip, 2123))


def hello(buff):
    seq_npdu=buff[8:11]
    gtpv1_resp="\x32\x02\x00\x06\x00\x00\x00\x00"+seq_npdu+"\x00\x0e\x00"
    socku.sendto(gtpv1_resp, (sgw_ip_s1, 2152))


class Rec(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self,name = "Rec")
        self.setDaemon(1)
    def run(self):
        while 1:
            buff = sockc.recv(16384)
            receiver(buff)


class GTPuEcho(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self,name = "GTPuEcho")
        self.setDaemon(1)
    def run(self):
        while 1:
            buff = socku.recv(16384)
            hello(buff)


def loop(stdscr):
    try:
        stdscr.clear()
        spin=0
        spin_tab = ["/","-","\\"]
        while 1:
            stdscr.addstr(2, 10, "SAE-GW Number of GTP Requests ", curses.A_STANDOUT)
            stdscr.addstr(2, 41, spin_tab[spin], curses.A_STANDOUT)
            spin = spin + 1
            if spin==3: spin=0 
            stdscr.addstr(3, 10, "Number:", curses.A_DIM)
            stdscr.addstr(3, 25, str(current_ip), curses.A_BOLD)
            stdscr.refresh()
            time.sleep(interval/2)
    except KeyboardInterrupt:
        print >>f, tab
        os.system("rmmod gtpu.ko")


os.system("rmmod gtpu.ko")
Rec().start()
GTPuEcho().start()
os.system("insmod gtpu.ko mode=0")
os.system("ip link set gtp0 up")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETSRC, struct.pack('16s4s', "gtp0", socket.inet_aton(sgw_ip_s1)))
fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETDST, struct.pack('16s4s', "gtp0", socket.inet_aton(enodeb_ip)))
fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETSAEPRFX, struct.pack('16s4s', "gtp0", socket.inet_aton(sae_prfx+"0")))
fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETTOS, struct.pack('16sB', "gtp0", dscp))
curses.wrapper(loop)


