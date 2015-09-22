#!/usr/bin/env python

import paramiko
import os
import getpass
import sys
import httplib
import socket
import re
import nmap
import xml.parsers.expat
import urllib2
import random
import requests
import time
import MultipartPostHandler, cookielib




class User(object):
    """Common class to store and manipulate user credentials"""
    def __init__(self,name=os.getenv('USERNAME'), ps=''):

        self.name = name
        self.ps = ps
        if ps == '':
            print "User name: %s" % self.name
            self.ps = getpass.getpass('Password or enter to skip and use keys instead of password: ')
        
    def setSSH(self, server):
        """Connects to ssh server and check auth returns ssh object"""

        self.server = server
        ssh=paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print "server: %s name: %s pass: %s" % (self.server, self.name, self.ps)
        
        try:
            ssh.connect(self.server,username=self.name,password=self.ps, look_for_keys = True)
        except:
            ssh.connect(self.server,username=self.name,password=self.ps, look_for_keys = False)
        
        return ssh

    def setILO(self, server):
        pass
    def setLDAP(self, server):
        pass
    def setMysql(self, server):
        pass



class Server(object):
    """Base class for host """
    def __init__(self,name,domain):
        self.name = name
        self.domain = domain

    #Methods
    def addToRack(self,rack_id):
        pass
    def addToLdap(self):
        pass


class HpServer(Server):
    """hp server that has ILO
        Minimum information is server name and ilo password from sticker
    """

    def __init__(self,name,domain,ilo_ip = '0'):
        Server.__init__(self,name,domain)
        
        self.ilo_ip = ilo_ip
        self.ilo_fw_bin = 'none'
        #Trivial method to get IP is the DNS request using server serial name all our ilos is in kvm.osmp.ru domain
        if self.ilo_ip == '0':
            try:
                self.ilo_ip = socket.gethostbyname(name+'.kvm.'+domain)
            except:
                print "Warning! this server has No address in DNS"+self.ilo_ip
                return
        
        try:
            conn = httplib.HTTPSConnection(self.ilo_ip, timeout=10)
            conn.request("GET", "/xmldata?item=all")
        except:
            print "Can't connect to: %s server: %s" % (self.ilo_ip, self.name)
            self.server_sn = self.model = self.fw_ver = self.ilo_model = 'null'
            return
            
        
        response = conn.getresponse()
        data = response.read()
        #print repr(data)

        pt = ['<SBSN>(.*)</SBSN>','<SPN>(.*)</SPN>','<FWRI>(.*)</FWRI>','<PN>(.*)</PN>']
        a = re.findall(pt[0], data)
        if a:
            self.server_sn = a.pop().rstrip()
        else:
            self.server_sn = 'null'

        a = re.findall(pt[1], data)
        if a:
            self.model = a.pop().rstrip()
        else:
            self.model = 'null'

        a = re.findall(pt[2], data)
        if a:
            self.fw_ver = a.pop().rstrip()
        else:
            self.fw_ver = 'null'

        a = re.findall(pt[3], data)
        if a:
            self.ilo_model = re.findall('\((iLO.*)\)',a.pop().rstrip()).pop().rstrip()
            #self.ilo_model = a.pop().rstrip()
        else:
            self.ilo_model = 'null'

        self.domain = domain

    def getIloSettings(self):
        DHCP_LEASE_F = '/var/lib/misc/dnsmasq.leases'
        #Deafault ilo name is ILO+servername
        #    ILO_NAME = 'ILOCZJ12800RW'

        user = User() #We use default user that's run a program with keys auth
        ssh = user.setSSH('jumpstart.e-port.ru')

        if ssh:
            stdin, stdout, stderr = ssh.exec_command('cat '+DHCP_LEASE_F+' | grep '+self.ilo_name)
            result = stdout.read()
            (id, self.ilo_mac, self.ilo_ip, name, mac) = result.split()
            ssh.close()
        else:
            return 0

        return result

    def setIloPass(self):
      
        user = User('Administrator')
        ssh = user.setSSH(self.ilo_ip)

#        if ssh:
        ilo_new_pass = getpass.getpass("Enter new ILO password: ")
        print 'Changing pass for %s %s' % (self.name, self.ilo_ip)
        stdin, stdout, stderr = ssh.exec_command('set map1/accounts1/Administrator password='+ilo_new_pass)
        self.ilo_pass = ilo_new_pass
        result = stdout.read().splitlines()
        ssh.close()
#        else:
#            return 0

        print repr(result)
        return 1

    def resetIlo(self):
        if (self.ilo_ip == 0):
            self.getIloSettings()
        user = User('Administrator')
        ssh = user.setSSH(self.ilo_ip)
        if ssh:
            stdin, stdout, stderr = ssh.exec_command('reset map1')
            result = stdout.read().splitlines()
            ssh.close()
        else:
            return 0

        print repr(result)
        return 1
    def manageIlo(self,pattern):
        """This method manage ILO using XML RIBCL interface
        XML templates must be located in XML directory under working tree
        """
        print "Attempt to manage %s IP: %s" % (self.name, self.ilo_ip)
        user = User('Administrator','pass')

        params_f = "./XML/" + pattern
        print params_f

        try:
            params = open(params_f,'r')
        except:
            print "Can't open file %s" % pattern
            exit(1)

        xml_import = ['<?xml version="1.0"?> \r\n']
        xml_import.append('<LOCFG version="2.21"> \r\n')
        for line in params:
            if (not re.search("<!--.*-->",line)) and (line != '\n') :  #skip comments
                if re.search("LOGIN USER_LOGIN",line):
                    xml_import.append('<LOGIN USER_LOGIN="'+user.name+'" PASSWORD="'+user.ps+'">\r\n')
                elif re.search("UPDATE_RIB_FIRMWARE IMAGE_LOCATION",line) and self.ilo_fw_bin != 'none':
                    xml_import.append('<UPDATE_RIB_FIRMWARE IMAGE_LOCATION="'+self.ilo_fw_bin+'"/>\r\n')
                else:
                    xml_import.append(line.rstrip()+ '\r\n')
                    
        xml_import.append('</LOCFG>')
        print xml_import
        
        #print "Checking ILO model and IP..."
        #print self.ilo_model
        #model = re.findall('\(iLO (\d)\)',self.ilo_model).pop().rstrip()
        #model = re.findall('\((iLO.*)\)',self.ilo_model).pop().rstrip()

        print self.ilo_ip, self.ilo_model
        
        if self.ilo_ip and (self.ilo_model == 'iLO' or self.ilo_model == 'iLO 2'):
            
            #print "Looks like this is ILO or ILO2"
            #ILO2
            PORT = 443 #default ssl port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # init TCP socket type
            s.connect((self.ilo_ip, PORT))
            sslSocket = socket.ssl(s)
            data = ''
            for line in xml_import:
                sslSocket.write(line)
                data = sslSocket.read() + data
            s.close()
            
            print repr(data)
            XMLParseOut(data)
        else:
            #print "Looks like this one is ILO3"
            #ILO3
            conn = httplib.HTTPSConnection(self.ilo_ip)
            headers = {}
            param = ''
            param = param.join(xml_import)
            conn.request("POST", "/ribcl", param, headers)
            response = conn.getresponse()
            #print response.status, response.reason
            data = response.read()
            print data
            XMLParseOut(data)
            conn.close()


    def updateFW(self, fwbin):
        """This method updates firmware for ilo2 ilo3
        The firmware binaries must resides in fw dir in subs ilo2 ilo3
        """
        # find fwbin in dir
        # get ilo ver and search in appropriate dir
        print self.ilo_model
        if (self.ilo_model == "iLO 2" or self.ilo_model == "iLO"):
            try:
                fw = open('ilo_fw/ilo2/'+fwbin,'rb')
                self.ilo_fw_bin = './ilo_fw/ilo2/'+fwbin
                fw.close()
                self.manageIlo("Update_Firmware.xml")
            except:
                print "Can't open ilo fw file! %s", fwbin
                exit(1)
        # form good XML to upload

        elif (self.ilo_model == "iLO 3"):
            try:
                fw = open('ilo_fw/ilo3/'+fwbin, 'rb')
                self.ilo_fw_bin = 'ilo_fw/ilo3/'+fwbin
            except :
                print "Can't open file %s" % self.ilo_fw_bin

        # Send FW
        self.sendFW(fw)
        # Fire UP manage with Update firmare XML template
        self.manageIlo("Update_Firmware.xml")


    def sendFW(self,fw):
        """ Send firmware image to ilo board
        """
        image_path = "/home/bushuev/svn/home/bushuev/"+self.ilo_fw_bin
        fwlength = os.path.getsize(image_path)
        sblocksize = 4*1024
        PORT = 443 #default ssl port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # init TCP socket type
        s.connect((self.ilo_ip, PORT))
        sslSocket = socket.ssl(s)
        boundary = "------hpiLO3t"+str(random.randint(1,1000000))+'z'

        body1 = "--"+boundary+"\r\nContent-Disposition: form-data; name=\"fileType\"\r\n"+"\r\n"
        body2 = "--"+boundary+"\r\nContent-Disposition: form-data; name=\"fwimgfile\"; filename=\""+image_path+"\"\r\nContent-Type: application/octet-stream\r\n"+"\r\n"
        body3 = "\r\n--"+boundary+"--\r\n"

        #!!!!!!
        sendsize = len(body1)+len(body2)+len(body3)+fwlength


        send_to_client(1, "POST /cgi-bin/uploadRibclFiles HTTP/1.1\r\n",sslSocket)
        send_to_client(1, "HOST: bushuev\r\n",sslSocket)
        send_to_client(1, "TE: chunked\r\n",sslSocket)
        send_to_client(1, "Connection: close\r\n",sslSocket)
        send_to_client(1, "Content-Length: "+str(sendsize)+"\r\n",sslSocket)
        send_to_client(1, "Content-Type: multipart/form-data; boundary="+boundary+"\r\n",sslSocket)
        send_to_client(1,"\r\n",sslSocket)
        send_to_client(1,body1,sslSocket)
        send_to_client(1,body2,sslSocket)

        # send firmware
        sentbytes = 0

        print "Start sendig firmware %d bytes" % fwlength

        for chunk in read_in_chunks(fw,sblocksize):
            #print sentbytes, len(chunk)
            send_to_client(0,chunk,sslSocket)
            if len(chunk) < sblocksize:
                sentbytes += len(chunk)
            else:
                sentbytes +=sblocksize
            print "\r %d bytes of firmware sent, (%3.2f)" % (sentbytes, float(sentbytes)*100/fwlength),

        send_to_client(1,body3,sslSocket)


        #All done close all sockets and file descriptors
        fw.close()
        # Get response from server
        read_responce(sslSocket,sblocksize)

        exit(1)

def read_responce(sslSocket, sblocksize):
    print "----- RESPONSES ----"
    cookie = ''
    for out in read_in_chunks(sslSocket,sblocksize):
        print out


def send_to_client(d,post,sslSocket):
    sslSocket.write(post)
    if d:
        print post,

def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data
                
def findIlo(ilo_net):
    """Scan ilo net for particular ILO address/name returns list of hp server objects"""
    hp_servers = []
    nm = nmap.PortScanner()
    #scan net for ilo virtual media port is the key assumes that we don't override it in ilo config:q
    nm.scan(ilo_net,'17988','-PN') 
    for h in nm.all_hosts():
        if nm[str(h)]['tcp'][17988]['state'] == 'open':
            # list of IP that have something looking like ILO :)
            #print 'SERVER %s -----------------' % str(h)
            #get damn server name aka sn
            try:
                conn = httplib.HTTPSConnection(str(h), timeout=5)
            except:
                print "Can't connect to %s skip" % str(h)
                continue
            try:
                conn.request("GET", "/xmldata?item=all")
                response = conn.getresponse()
            except:
                print "can't get response from %s" % str(h)
                conn.close()
                continue
                
            data = response.read()
            a = re.findall('<SBSN>(.*)</SBSN>', data)
            conn.close
            if a:
                server_sn = a.pop().rstrip()
                print "Found server %s with ILO module" % server_sn
                hp_serv = HpServer(server_sn,'osmp.ru',str(h))
                hp_servers.append(hp_serv)

            #if list_all == 1:
            #    print "IP: %s Serial: %s Model: %s ILO FW: %s ILO Model: %s" % (str(h), server_sn, model, fw_ver, ilo_model)
    return hp_servers

def XMLParseOut(data):
    """   parse xml
    """
    def start_element(name, attrs):
        if name == "RIBCL" or name == "INFORM":
            return 0
        if 'STATUS' in attrs and attrs['STATUS'] == '0x0000':
            return 0
        print 'element:', name
        for key in attrs.keys():
            print str(key), str(attrs[key])

    def end_element(name):
        print 'End element:', name
    def char_data(data):
        if data.rstrip():
            print 'Character data:', repr(data)

    arr = data.split('<?xml version="1.0"?>')
    for chunk in arr:
        p = xml.parsers.expat.ParserCreate()
        p.StartElementHandler = start_element
        #    p.EndElementHandler = end_element
        p.CharacterDataHandler = char_data
        try:
            p.Parse(chunk,1)
        except :
            pass

if __name__ == "__main__":

#    person = User('Administrator')
#    print person.name, person.ps
    

    
    #fd = open('/home/bushuev/sss')
    
    #for l in fd:
        #print l.rstrip()
    #    serv = HpServer(l.rstrip() ,'osmp.ru')
    #    print serv.ilo_ip, serv.name
    #    serv.manageIlo('Add_User.xml')
   
   
    serv = findIlo('10.7.64.0/23')

    for i in serv:
        print "Serial: %s ILO Address: %s ILO Version %s ILO Model %s" % (i.name, i.ilo_ip, i.fw_ver, i.ilo_model)
        i.manageIlo('Mod_Directory.xml')

    #problem_servers = ('CZJ03600Z2')

    #srv = HpServer('GB883838RJ','osmp.ru')
    #for i in problem_servers:
    #    srv = HpServer(i, 'osmp.ru')
    #srv.manageIlo('Get_User.xml')
    #srv.manageIlo('Get_User.xml')

    #for s in serv:
    #    s.manageIlo('Mod_Directory.xml')

    #srv.manageIlo('Mod_Directory.xml')
    #srv.updateFW('ilo3_128.bin')
    #srv.updateFW('fake.bin')
    
    #    print "IP: %s Serial: %s Model: %s ILO FW: %s ILO Model: %s" % (i.ilo_ip, i.name, i.model, i.fw_ver, i.ilo_model)
    
        
    #serv = HpServer('CZJ03600ZS','osmp.ru')
    #print serv.ilo_ip
    #serv.manageIlo('Get_UID_Status.xml')

