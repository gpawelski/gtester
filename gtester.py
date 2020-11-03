#! /usr/bin/env python

#    This is gtester.py - client for GTP tunnel creation straight from your computer
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

mme_ip = "192.168.17.128"	#local address S11
enodeb_ip = "192.168.17.128"	#local address S1U

sgw_ip_s11 = "192.168.18.200"	#remote address S11
sgw_ip_s1 = "192.168.19.200"	#remote address S1U
pgw_ip = "192.168.20.200"	#PDN-GW address
mobile_ip = "0.0.0.0"		#mobile address, static or "0.0.0.0" if assigned by PDN-GW
route = 'default'		#route to be setup on the GTP tunnel e.g. 10.10.0.0/16 or default

apn = "123.nsn.com"

imsi = 260669900000069
msisdn = 801000065

ambr_up = 50000000
ambr_down = 150000000
qci = 0
max_up = 50000000
max_down = 150000000
guaranteed_up = 0
guaranteed_down = 0

mcc = 260
mnc = 66
tac = 20
eci = '000001'

dscp = 0x00			#DSCP for GTP-U pkts


########################################################################

import struct, socket, threading, time, select, curses, fcntl, os, sys, string
from gtpv2 import *

teid = 1
interval = 2
number = 1

tab = {}
tab[0] = [0, 0, 0, "0.0.0.0", 0]
sent = 0
succesful = 0

sockc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockc.setblocking(True)
sockc.bind((mme_ip, 2123))

socku = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socku.setblocking(True)
socku.bind((enodeb_ip, 2152))

f = open('out.txt','w')

m_cre_req = GTP_CREATE_SESS_REQ()
m_cre_res = GTP_CREATE_SESS_RES()
m_mod_req = GTP_MODIFY_BEAR_REQ()
m_mod_res = GTP_MODIFY_BEAR_RES()


def hello(buff):
    seq_npdu=buff[8:11]
    gtpv1_resp="\x32\x02\x00\x06\x00\x00\x00\x00"+seq_npdu+"\x00\x0e\x00"
    socku.sendto(gtpv1_resp, (sgw_ip_s1, 2152))


def setup_gtpu():
    os.system("insmod gtpu.ko mode=1")
    os.system("ip link set gtp0 up")
    os.system("ip add add "+mobile_ip+" dev gtp0")
    os.system("ip route add "+route+" dev gtp0")
    fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETTEID, struct.pack('16sI', "gtp0", m_mod_res.bearer_ctxt.f_teid.teid))
    fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETSRC, struct.pack('16s4s', "gtp0", socket.inet_aton(enodeb_ip)))
    fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETDST, struct.pack('16s4s', "gtp0", socket.inet_aton(sgw_ip_s1)))
    fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), SETTOS, struct.pack('16sB', "gtp0", dscp))


def receiver(buff):
    global succesful
    global mobile_ip
    head_in = GTP_HEAD()
    head_in.dec(buff[0:12])
    if head_in.version == 2 and head_in.type == CREATE_SESS_RES:
       m_cre_res.dec(buff)
       m_mod_req.indication.enc(0x0)
       if m_cre_res.f_teid.typ == TEID_SGW:
           teid_sgw = m_cre_res.f_teid.teid
       elif m_cre_res.f_teid1.typ == TEID_SGW:
           teid_sgw = m_cre_res.f_teid1.teid
       m_mod_req.f_teid.enc(TEID_MME, teid, mme_ip)
       m_mod_req.bearer_ctxt.ebi.enc(m_cre_res.bearer_ctxt.ebi.ebi)
       m_mod_req.bearer_ctxt.f_teid.enc(TEID_ENBU, teid, enodeb_ip)
       m_mod_req.bearer_ctxt.enc()
       m_mod_req.charg_char.enc(0x03100)
       m_mod_req.enc(teid_sgw, head_in.seq, head_in.spare)
       sockc.sendto(m_mod_req.out, (sgw_ip_s11, 2123))
       mobile_ip = m_cre_res.pdn_addr.address
       tab[head_in.teid][0] = m_cre_res.cause.cause
       tab[head_in.teid][1] = teid_sgw
       tab[head_in.teid][3] = mobile_ip
       tab[head_in.teid][4] = m_cre_res.bearer_ctxt.f_teid.teid
    elif head_in.version == 2 and head_in.type == MODIFY_BEAR_RES:
         m_mod_res.dec(buff)
         tab[head_in.teid][2] = m_mod_res.cause.cause
         if m_mod_res.cause.cause==CAUSE_REQ_ACCEPTED:
            succesful=succesful+1
            setup_gtpu()
    elif head_in.version == 2 and head_in.type == ECHO_REQ:
         sequen = buff[4:8]
         gtpv2_resp = "\x40\x02\x00\x09"+sequen+"\x03\x00\x01\x00\x01"
         sockc.sendto(gtpv2_resp, (sgw_ip_s11, 2123))


class Gen(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self,name = "Gen")
        self.setDaemon(1)
    def run(self):
        global sent
        m_cre_req.imsi.enc(imsi)
        m_cre_req.msisdn.enc(msisdn)
        m_cre_req.uli.enc(mcc, mnc, tac, mcc, mnc, eci)
        m_cre_req.servin_net.enc(mcc, mnc)
        m_cre_req.rat_type.enc(6)
        m_cre_req.indication.enc(0x4)
        m_cre_req.f_teid.enc(TEID_MME, teid, mme_ip)
        m_cre_req.f_teid1.enc(TEID_S5PGW, 0, pgw_ip)
        m_cre_req.apn.enc(apn)
        m_cre_req.sel_mode.enc(0xfc)
        m_cre_req.pdn_type.enc(0x1)
        m_cre_req.pdn_addr.enc(mobile_ip)
        m_cre_req.apn_restr.enc(0)
        m_cre_req.ambr.enc(ambr_up, ambr_down)
        m_cre_req.pco.enc('8080210a0100000a810600000000')
        m_cre_req.bearer_ctxt.ebi.enc(5)
        m_cre_req.bearer_ctxt.bearer_qos.enc(0, qci, max_up, max_down, guaranteed_up, guaranteed_down)
        m_cre_req.bearer_ctxt.enc()
        m_cre_req.recovery.enc(1)
        m_cre_req.charg_char.enc(256)
        m_cre_req.enc(0, 0, 0)
        sockc.sendto(m_cre_req.out, (sgw_ip_s11, 2123))
        sent=sent+1
        tab[teid] = [0, 0, 0, "0.0.0.0", 0]    #key local teid: [create cause, teid s11, modify cause, pdn_addr, teid s1u]


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
            stdscr.addstr(2, 10, "GTPTEST Number of GTP Requests ", curses.A_STANDOUT)
            stdscr.addstr(2, 41, spin_tab[spin], curses.A_STANDOUT)
            spin = spin + 1
            if spin==3: spin=0 
            stdscr.addstr(3, 10, "Sent:", curses.A_DIM)
            stdscr.addstr(3, 25, str(sent), curses.A_BOLD)
            stdscr.addstr(3, 35, "of "+str(number), curses.A_DIM)
            stdscr.addstr(4, 10, "Succesful:", curses.A_DIM)
            stdscr.addstr(4, 25, str(succesful), curses.A_BOLD)
            stdscr.addstr(4, 35, "of "+str(sent), curses.A_DIM)
            stdscr.refresh()
            time.sleep(interval/2)
    except KeyboardInterrupt:
        print >>f, tab
        os.system("rmmod gtpu.ko")


os.system("rmmod gtpu.ko")
Gen().start()
Rec().start()
GTPuEcho().start()
curses.wrapper(loop)


