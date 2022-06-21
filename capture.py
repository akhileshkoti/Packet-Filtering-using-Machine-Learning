import pyshark
import time
import joblib
import os
from subprocess import call

capture = pyshark.LiveCapture(display_filter='icmp')
model = joblib.load('random forest')
count={}
l=[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]
for pac in capture.sniff_continuously():
    l[0][2]=pac.icmp.code
    if(l[0][2]==0):
        l[0][4]=pac.captured_length
    elif(l[0][2]==8):
        l[0][3]=pac.captured_length
    if(pac.ip.flags=='0x20'):
        l[0][7]=1
    x=model.predict(l)
    if(x != ['normal']):
        print("Intrusion")
        print('blocking the src ip',pac.ip.src)
        string='netsh advfirewall firewall add rule name="Block Address-'+pac.ip.src+'" dir=in action=block remoteip='+pac.ip.src        #print(string)
        #os.system("netsh advfirewall firewall add rule name='Block Address-'"+pac.ip.src+'dir=in action=block remoteip='+'\"'+pac.ip.src+'\"')
        #process=Popen(['cmd.exe','netsh advfirewall firewall add rule name="Block Ip Address-'+pac.ip.src+'" dir=in action=block remoteip='+pac.ip.src],stdin=PIPE,stdout=PIPE,stderr=PIPE)
        #process=call(string,shell=False)
        os.system(string)
        continue
    if((pac.ip.src,pac.ip.dst,x[0]) not in count.keys()):
        count.update({(pac.ip.src,pac.ip.dst,x[0]):1})
    else:
        count[(pac.ip.src,pac.ip.dst,x[0])]+=1
        if(count[(pac.ip.src,pac.ip.dst,x[0])]>20):
            print("Blocking the src ip",pac.ip.src)
            string='netsh advfirewall firewall add rule name="Block Address-'+pac.ip.src+'" dir=in action=block remoteip='+pac.ip.src
            print(string)
            os.system(string)
            break
            #print(string)
            #process=Popen(['cmd.exe','netsh advfirewall firewall add rule name="Block Ip Address-'+pac.ip.src+'" dir=in action=block remoteip='+pac.ip.src],stdin=PIPE,stdout=PIPE,stderr=PIPE)
            #process=call(string,shell=False)
            

