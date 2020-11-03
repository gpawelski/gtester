#    This is gtpv2.py
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



import struct, socket, threading, time, select, curses, fcntl, os, sys, string, binascii



############################# "CONSTANTS" ###############################


CREATE_SESS_REQ = 32
CREATE_SESS_RES = 33
MODIFY_BEAR_REQ = 34
MODIFY_BEAR_RES = 35
DELETE_SESS_REQ = 36
DELETE_SESS_RES = 37
RELEAS_BEAR_REQ = 170
RELEAS_BEAR_RES = 171
ECHO_REQ = 1
ECHO_RES = 2

IE_IMSI = 1
IE_CAUSE = 2
IE_RECOVERY = 3
IE_APN = 71
IE_AMBR = 72
IE_EBI = 73
IE_MSISDN = 76
IE_INDICATION = 77
IE_PCO = 78
IE_PDN_ADDR = 79
IE_BEARER_QOS = 80
IE_RAT_TYPE = 82
IE_SERVIN_NET = 83
IE_ULI = 86
IE_F_TEID = 87
IE_BEARER_CTXT = 93
IE_CHARG_CHAR = 95 
IE_PDN_TYPE = 99
IE_APN_RESTR = 127
IE_SEL_MODE = 128

CAUSE_REQ_ACCEPTED = 16

TEID_MME = 0x8a
TEID_SGW = 0x8b
TEID_S5PGW = 0x89
TEID_ENBU = 0x80
TEID_SGWU = 0x81

SETTEID=0x89f1
SETSRC=0x89f2
SETDST=0x89f3
SETSAEPRFX=0x89f4
SETSAEIP=0x89f5
SETSAETEID=0x89f6
SETTOS=0x89f7


############################## GENERAL ROUTINES #####################################

def int_conv(value):
   strin = '%d'% (value)
   numb = ''
   for j in range(0,len(strin)):
      if j % 2 == 0:
          tmp = strin[j]
      else:
          numb = numb + strin[j] + tmp
   if len(strin) % 2 == 1:
      numb = numb + 'f' + tmp           
   return binascii.a2b_hex(numb)


def mcc_mnc(mcc, mnc):
   smcc = '%d'% (mcc)
   smnc = '%d'% (mnc)
   if len(smnc) == 1: 
      numb = smcc[1] + smcc[0] + 'f' + smcc[2] + smnc[0] + '0'
   elif len(smnc) == 2:
      numb = smcc[1] + smcc[0] + 'f' + smcc[2] + smnc[1] + smnc[0]
   elif len(smnc) == 3:
      numb = smcc[1] + smcc[0] + smnc[0] + smcc[2] + smnc[2] + smnc[1]
   return binascii.a2b_hex(numb)
   

def searchIE(type,inst,buff):
    i = 0
    while i < len(buff):
        (type_dec,) = struct.unpack('!B',buff[i])
        (length,) = struct.unpack('!H',buff[i+1:i+3])
        (inst_dec,) = struct.unpack('!B',buff[i+3])
        inst_dec = inst_dec & 0x0f
        if type_dec == type and inst_dec == inst:
           return buff[i:i+4+length]
        else:
           i = i + length + 4
    return None


class AVP(object):
   def __init__(self, instance):
       self.inst = instance
   def enc_avps(self):
       avps = ""
       for avp in self.lst:
          avps = avps + vars(self)[avp].out 
       return avps
   def dec_avps(self, input):
      for avp in self.lst: 
         ie_buff = searchIE(vars(self)[avp].ietyp,vars(self)[avp].inst,input[4:])
         if ie_buff != None:
            vars(self)[avp].dec(ie_buff)

      
class GTP_HEAD(object):
   def enc(self, t, p, version, type, length, teid, seq, spare=None):
       byte1 = (t & 1) << 3
       byte1 = byte1 | ((p & 1) << 4)
       byte1 = byte1 | ((version & 3) << 5)
       byte2 = type
       byte3_4 = length
       byte5_8 = teid
       byte9_10 = seq
       byte11_12 = spare 
       self.out = struct.pack('!BBHIHH', byte1, byte2, byte3_4, byte5_8, byte9_10, byte11_12)
   def dec(self, input):
       (byte1, byte2, byte3_4, byte5_8, byte9_10, byte11_12) = struct.unpack('!BBHIHH', input)
       self.t = (byte1 >> 3) & 1 
       self.p = (byte1 >> 4) & 1
       self.version = (byte1 >> 5) & 3
       self.type = byte2
       self.length = byte3_4
       self.teid = byte5_8
       self.seq = byte9_10
       self.spare = byte11_12       


class GTP_MSG(object):
   head = GTP_HEAD()
   def enc(self, teid, seq, spare):
      payload = ""
      for ie in self.ies:
         payload = payload + ie.out 
      self.head.enc(1,0,2,self.typ,len(payload)+8,teid,seq,spare) 
      self.out = self.head.out + payload
   def dec(self, buff):
      self.head.dec(buff[0:12]) 
      for i,ie in enumerate(self.ies): 
         ie_buff = searchIE(ie.ietyp,ie.inst,buff[12:])
         if ie_buff != None:
            self.ies[i].dec(ie_buff)



################################ AVPs ###################################

class CAUSE(AVP):
   ietyp = IE_CAUSE
   def enc(self, cause, source):
       self.out = struct.pack('!BHBBB', self.ietyp, 2, self.inst, cause, source)
   def dec(self, input):
       (_,_,_,self.cause, self.source) = struct.unpack('!BHBBB', input)   
 
class IMSI(AVP):
   ietyp = IE_IMSI
   def enc(self, value):
       imsi = int_conv(value)
       self.out = struct.pack('!BHB%ds' % (len(imsi),), self.ietyp, len(imsi), self.inst, imsi)
   def dec(self, input):
       pass

class MSISDN(AVP):
   ietyp = IE_MSISDN
   def enc(self, value):
       msisdn = int_conv(value)
       self.out = struct.pack('!BHBc%ds' % (len(msisdn),), self.ietyp, len(msisdn)+1, self.inst, '\x53' , msisdn)
   def dec(self, input):
       pass

class F_TEID(AVP):
   ietyp = IE_F_TEID
   def enc(self, typ, teid, address):
       self.out = struct.pack('!BHBBI4s', self.ietyp, 9, self.inst, typ, teid, socket.inet_aton(address))
   def dec(self, input):
       (_,_,_, self.typ, self.teid, self.address) = struct.unpack('!BHBBI4s', input)
       self.address = socket.inet_ntoa(self.address)

class PDN_ADDR(AVP):
   ietyp = IE_PDN_ADDR
   def enc(self, address):
       self.out = struct.pack('!BHBB4s', self.ietyp, 5, self.inst, 1, socket.inet_aton(address))
   def dec(self, input):
       (_,_,_,_, self.address) = struct.unpack('!BHBB4s', input)       
       self.address = socket.inet_ntoa(self.address)

class BEARER_QOS(AVP):
   ietyp = IE_BEARER_QOS
   def enc(self, flags, qci, max_up, max_down, g_up, g_max):
       self.out = struct.pack('!BHBBBBIBIBIBI', self.ietyp, 22, self.inst, flags, qci, 0, max_up, 0, max_down, 0, g_up, 0, g_max)
   def dec(self, input):
       pass

class EBI(AVP):
   ietyp = IE_EBI
   def enc(self, ebi):
       self.out = struct.pack('!BHBB', self.ietyp, 1, self.inst, ebi)
   def dec(self, input):
       (_,_,_, self.ebi) = struct.unpack('!BHBB', input)      

class BEARER_CTXT(AVP):
   ietyp = IE_BEARER_CTXT
   def __init__(self, instance, ls):
       self.inst = instance
       self.lst = ls
       self.ebi = EBI(0)
       self.bearer_qos = BEARER_QOS(0)
       self.cause = CAUSE(0)
       self.f_teid = F_TEID(0)
   def enc(self):
       self.out = struct.pack('!BHB', self.ietyp, len(self.enc_avps()), self.inst) + self.enc_avps()
   def dec(self, input):
       self.dec_avps(input)

class AMBR(AVP):
   ietyp = IE_AMBR
   def enc(self, max_up, max_down):
       self.out = struct.pack('!BHBII', self.ietyp, 8, self.inst, max_up, max_down)
   def dec(self, input):
       pass

class APN(AVP):
   ietyp = IE_APN
   def enc(self, inp):
       length = len(inp)+1
       apn = ""
       tab = inp.split('.')
       for label in tab:
           label = struct.pack('B%ds' % (len(label),), len(label), label)
           apn = apn + label
       self.out = struct.pack('!BHB'+str(length)+'s', self.ietyp, length, self.inst, apn)
   def dec(self, input):
       pass

class RECOVERY(AVP):
   ietyp = IE_RECOVERY
   def enc(self, value):
       self.out = struct.pack('!BHBB', self.ietyp, 1, self.inst, value)
   def dec(self, input):
       (_,_,_, self.value) = struct.unpack('!BHBB', input)

class ULI(AVP):
   ietyp = IE_ULI
   def enc(self, mcc, mnc, tac, mcc1, mnc1, eci):
       self.out = struct.pack('!BHBB3sH3s3sB', self.ietyp, 13, self.inst, 0x18, mcc_mnc(mcc, mnc), tac, mcc_mnc(mcc1, mnc1), binascii.a2b_hex(eci), 0x10)
   def dec(self, input):
       pass

class SERVIN_NET(AVP):
   ietyp = IE_SERVIN_NET
   def enc(self, mcc, mnc):
       self.out = struct.pack('!BHB3s', self.ietyp, 3, self.inst, mcc_mnc(mcc, mnc))
   def dec(self, input):
       pass

class RAT_TYPE(AVP):
   ietyp = IE_RAT_TYPE
   def enc(self, rat_typ):
       self.out = struct.pack('!BHBB', self.ietyp, 1, self.inst, rat_typ)
   def dec(self, input):
       pass

class INDICATION(AVP):
   ietyp = IE_INDICATION
   def enc(self, indic):
       self.out = struct.pack('!BHBH', self.ietyp, 2, self.inst, indic)
   def dec(self, input):
       pass

class SEL_MODE(AVP):
   ietyp = IE_SEL_MODE
   def enc(self, select):
       self.out = struct.pack('!BHBB', self.ietyp, 1, self.inst, select)
   def dec(self, input):
       pass

class PDN_TYPE(AVP):
   ietyp = IE_PDN_TYPE
   def enc(self, typ):
       self.out = struct.pack('!BHBB', self.ietyp, 1, self.inst, typ)
   def dec(self, input):
       pass

class APN_RESTR(AVP):
   ietyp = IE_APN_RESTR
   def enc(self, restr):
       self.out = struct.pack('!BHBB', self.ietyp, 1, self.inst, restr)
   def dec(self, input):
       pass

class PCO(AVP):
   ietyp = IE_PCO
   def enc(self, input):
       pco = binascii.a2b_hex(input)
       self.out = struct.pack('!BHB%ds' %(len(pco),), self.ietyp, len(pco), self.inst, pco)
   def dec(self, input):
       pass

class CHARG_CHAR(AVP):
   ietyp = IE_CHARG_CHAR
   def enc(self, charact):
       self.out = struct.pack('!BHBH', self.ietyp, 2, self.inst, charact)
   def dec(self, input):
       pass

################################ MESSAGES #######################################

class GTP_CREATE_SESS_REQ(GTP_MSG):
   typ = CREATE_SESS_REQ
   imsi = IMSI(0)
   msisdn = MSISDN(0)
   uli = ULI(0)
   servin_net = SERVIN_NET(0)
   rat_type = RAT_TYPE(0)
   indication = INDICATION(0)
   f_teid = F_TEID(0)
   f_teid1 = F_TEID(1)
   apn = APN(0)
   sel_mode = SEL_MODE(0)
   pdn_type = PDN_TYPE(0) 
   pdn_addr = PDN_ADDR(0)
   apn_restr = APN_RESTR(0)
   ambr = AMBR(0)
   pco = PCO(0)
   bearer_ctxt = BEARER_CTXT(0, ['ebi','bearer_qos'])
   recovery = RECOVERY(0)
   charg_char = CHARG_CHAR(0)
   ies = (imsi, msisdn, uli, servin_net, rat_type, indication, f_teid, f_teid1, apn, sel_mode, pdn_type, pdn_addr, apn_restr, ambr, pco, bearer_ctxt, recovery, charg_char)  

class GTP_CREATE_SESS_RES(GTP_MSG):
   typ = CREATE_SESS_RES
   cause = CAUSE(0)
   f_teid = F_TEID(0)
   f_teid1 = F_TEID(1)
   pdn_addr = PDN_ADDR(0)
   apn_restr = APN_RESTR(0)
   pco = PCO(0)
   bearer_ctxt = BEARER_CTXT(0, ['ebi','cause','f_teid'])
   ies = (cause, f_teid, f_teid1, pdn_addr, apn_restr, pco, bearer_ctxt)

class GTP_MODIFY_BEAR_REQ(GTP_MSG):
   typ = MODIFY_BEAR_REQ
   indication = INDICATION(0)
   f_teid = F_TEID(0)
   bearer_ctxt = BEARER_CTXT(0, ['ebi','f_teid'])
   charg_char = CHARG_CHAR(0)
   ies = (indication, f_teid, bearer_ctxt, charg_char)

class GTP_MODIFY_BEAR_RES(GTP_MSG):
   typ = MODIFY_BEAR_RES
   cause = CAUSE(0)
   bearer_ctxt = BEARER_CTXT(0, ['ebi','cause','f_teid'])
   ies = (cause, bearer_ctxt)

class GTP_DELETE_SESS_REQ(GTP_MSG):
   typ = DELETE_SESS_REQ
   ebi = EBI(0)
   ies = (ebi,)

class GTP_DELETE_SESS_RES(GTP_MSG):
   typ = DELETE_SESS_RES
   cause = CAUSE(0)
   ies = (cause,)

class GTP_RELEAS_BEAR_REQ(GTP_MSG): 
   typ = RELEAS_BEAR_REQ
   ies = ()

class GTP_RELEAS_BEAR_RES(GTP_MSG):
   typ = RELEAS_BEAR_RES
   cause = CAUSE(0)
   ies = (cause,)
