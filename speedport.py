import requests
import hashlib
import json
import argparse
from argparse import RawTextHelpFormatter

class bcol:
    red='\33[91m'
    lgreen='\33[92m'
    reset='\33[0m'
    bold='\33[1m'
    dblue='\33[34m'
headers={
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE",
    "Accept-Encoding": "gzip, deflate"
}
purl="127.0.0.1:8080"
p={
              "http"  : "http://"+purl,
              "https" : "https://"+purl,
              "ftp"   :  "ftp://"+purl
}
url="http://192.168.2.1"

def hash(val):
    m=hashlib.sha256()
    m.update(val)
    return m.hexdigest()

def login(password):
    global headers
    global purl
    global p
    global url
    ls=requests.get(url=url,headers=headers,verify=False,allow_redirects=True)
    cc=ls.text.find("challenge")
    chal=ls.text[cc:cc+80].split("\"")[1]
    hashv=hash((chal+":"+password).encode("utf-8"))
    data={
        "csrf_token":"nulltoken",
        "password": hashv,
        "showpw":"0",
        "challengev":chal
    }
    lr=requests.post(url=url+"/data/Login.json",headers=headers,data=data,verify=False,allow_redirects=True)
    return lr.cookies

def getCsrf(session_c):
    global headers
    global purl
    global p
    global url
    cr=requests.get(url=url+"/html/content/overview/index.html?lang=de",headers=headers,cookies=session_c,verify=False,allow_redirects=True)
    raw=cr.text.find("csrf_token")
    return cr.text[raw:raw+55].split("\"")[1]

def blockTraffic(ip,csrf,session_c,name):
    global headers
    global purl
    global p
    global url
    try:
        dr=requests.get(url=url+"/data/FilterAndTime.json",headers=headers,cookies=session_c,verify=False,allow_redirects=True)
        jst=json.loads(dr.text)
        data3={
            "csrf_token":csrf,
            "extendedrule_active":"1",
            "extrule_name":name,
            "disallow_tcp":"1",
            "disallow_udp":"1",
            "disallow_http":"0",
            "disallow_https":"0",
            "disallow_smtp":"0",
            "disallow_pop":"0",
            "disallow_nntp":"0",
            "disallow_ftp":"0",
            "disallow_telnet":"0",
            "disallow_dns":"0",
            "disallow_snmp":"0",
            "disallow_vpnpptp":"0",
            "disallow_vpnl2tp":"0",
            "id":"-1"
        }
        count=1
        sid=[]
        for x in range(0,len(jst)):
            if jst[x]['varid']=="extrarule_addmdevice":
                if jst[x]['varvalue'][5]['varvalue']==ip:
                    data3["mdevice_name["+str(count)+"1]"]="1"
                else:
                    data3["mdevice_name[" + str(count) + "1]"]= "0"
                sid.append(jst[x]['varvalue'][0]['varvalue'])
                count=count+1

        for i in range(0, len(sid)):
            data3["sid[" + str(i+1) + "1]"] = sid[i]
        br=requests.post(url=url+"/data/ExtendedRules.json?lang=de",headers=headers,cookies=session_c,data=data3,verify=False,allow_redirects=True)
        resp=json.loads(br.text)
        if resp[1]["varvalue"]=="ok":
            print(bcol.lgreen+"[+] Blocker set successfully!"+bcol.reset)
        else:
            print(bcol.red+"[-] Error, can't set blocker!"+bcol.reset)
    except json.decoder.JSONDecodeError:
        print(bcol.red + "[-] Error, maybe there isn't a device with specified ip connected." + bcol.reset)

def deleteBlocker(name,session_c,csrf):
    global headers
    global purl
    global p
    global url
    dr = requests.get(url=url + "/data/FilterAndTime.json", headers=headers, cookies=session_c, verify=False,allow_redirects=True)
    jst = json.loads(dr.text)
    id="noid"
    for x in range(0, len(jst)):
        if jst[x]['varid'] == "addextra":
            if jst[x]['varvalue'][2]['varvalue'] == name:
                id=jst[x]['varvalue'][0]['varvalue']

    if not id=="noid":
        data={
            "id":id,
            "deleteEntry":"delete",
            "csrf_token":csrf
        }
        der = requests.post(url=url + "/data/ExtendedRules.json?lang=de", headers=headers, cookies=session_c, data=data, verify=False, allow_redirects=True)
        resp = json.loads(der.text)
        if resp[1]["varvalue"] == "ok":
            print(bcol.lgreen+"[+] Blocker deleted successfully!"+bcol.reset)
        else:
            print(bcol.red+"[-] Error while deleting!"+bcol.reset)
    else:
        print(bcol.red + "[-]No device with specified IP found!" + bcol.reset)

def addPortForward(pport,privp,protocol,ip,session_c,csrf):
    global headers
    global purl
    global p
    global url
    pr=requests.get(url=url+"/data/Portforwarding.json",headers=headers,cookies=session_c,verify=False,allow_redirects=True)
    jst=json.loads(pr.text)
    id="no"
    for x in range(0, len(jst)):
        if jst[x]['varid'] == "dynrule_addmdevice":
            if jst[x]['varvalue'][5]['varvalue'] == ip:
                id=jst[x]['varvalue'][0]['varvalue']

    if not id=="no":
        if protocol=="tcp":
            tid=[]
            pubfp=[]
            pubtp=[]
            intp=[]
            act=[]
            devid=[]
            for x in range(0, len(jst)):
                if jst[x]['varid'] == "addtcpredirect":
                    tid.append(jst[x]['varvalue'][0]['varvalue'])
                    pubfp.append(jst[x]['varvalue'][1]['varvalue'])
                    pubtp.append(jst[x]['varvalue'][2]['varvalue'])
                    intp.append(jst[x]['varvalue'][3]['varvalue'])
                    act.append(jst[x]['varvalue'][4]['varvalue'])
                    devid.append(jst[x]['varvalue'][5]['varvalue'])
            pdata={
                "csrf_token":csrf
            }

            tid.append("-1")
            pubfp.append(pport)
            pubtp.append(pport)
            intp.append(privp)
            act.append("1")
            devid.append(id)

            for x in range(0,len(act)):
                pdata["tcp_redirect_active["+str(x+1)+"]"]=act[x]
            for x in range(0,len(pubfp)):
                pdata["tcp_public_from["+str(x+1)+"]"]=pubfp[x]
            for x in range(0,len(pubtp)):
                pdata["tcp_public_to["+str(x+1)+"]"]=pubtp[x]
            for x in range(0,len(intp)):
                pdata["tcp_private_dest["+str(x+1)+"]"]=intp[x]
            for x in range(0,len(devid)):
                pdata["tcp_device["+str(x+1)+"]"]=devid[x]
            rid=0
            for x in range(0,len(tid)):
                pdata["tcpredirect_id["+str(x+1)+"]"]=tid[x]
                rid=x
            ppr = requests.post(url=url + "/data/Portforwarding.json?lang=de", headers=headers, cookies=session_c,data=pdata, verify=False, allow_redirects=True)
            jsre=json.loads(ppr.text)
            if jsre[3]['varvalue']['MultiDatabaseSink_0'][rid]['varvalue'][1]['varvalue']=="ok":
                print(bcol.lgreen+"[+]Port redirect successfully set!"+bcol.reset)
            else:
                print(bcol.red+"[-]Port redirect failed"+bcol.reset)
        elif protocol=="udp":
            tid = []
            pubfp = []
            pubtp = []
            intp = []
            act = []
            devid = []
            for x in range(0, len(jst)):
                if jst[x]['varid'] == "addudpredirect":
                    tid.append(jst[x]['varvalue'][0]['varvalue'])
                    pubfp.append(jst[x]['varvalue'][1]['varvalue'])
                    pubtp.append(jst[x]['varvalue'][2]['varvalue'])
                    intp.append(jst[x]['varvalue'][3]['varvalue'])
                    act.append(jst[x]['varvalue'][4]['varvalue'])
                    devid.append(jst[x]['varvalue'][5]['varvalue'])
            pdata = {
                "csrf_token": csrf
            }

            tid.append("-1")
            pubfp.append(pport)
            pubtp.append(pport)
            intp.append(privp)
            act.append("1")
            devid.append(id)

            for x in range(0, len(act)):
                pdata["udp_redirect_active[" + str(x + 1) + "]"] = act[x]
            for x in range(0, len(pubfp)):
                pdata["udp_public_from[" + str(x + 1) + "]"] = pubfp[x]
            for x in range(0, len(pubtp)):
                pdata["udp_public_to[" + str(x + 1) + "]"] = pubtp[x]
            for x in range(0, len(intp)):
                pdata["udp_private_dest[" + str(x + 1) + "]"] = intp[x]
            for x in range(0, len(devid)):
                pdata["udp_device[" + str(x + 1) + "]"] = devid[x]
            rid = 0
            for x in range(0, len(tid)):
                pdata["udpredirect_id[" + str(x + 1) + "]"] = tid[x]
                rid = x
            ppr = requests.post(url=url + "/data/Portforwarding.json?lang=de", headers=headers, cookies=session_c, data=pdata, verify=False, allow_redirects=True)
            jsre = json.loads(ppr.text)
            if jsre[3]['varvalue']['MultiDatabaseSink_0'][rid]['varvalue'][1]['varvalue'] == "ok":
                print(bcol.lgreen + "[+]Port redirect successfully set!" + bcol.reset)
            else:
                print(bcol.red + "[-]Port redirect failed" + bcol.reset)
    else:
        print(bcol.red + "[-]No device with specified IP found!" + bcol.reset)

def deletePortForward(pport,protocol,ip,session_c,csrf):
    global headers
    global purl
    global p
    global url
    pr = requests.get(url=url + "/data/Portforwarding.json", headers=headers, cookies=session_c, verify=False, allow_redirects=True)
    jst=json.loads(pr.text)
    id = "no"
    for x in range(0, len(jst)):
        if jst[x]['varid'] == "dynrule_addmdevice":
            if jst[x]['varvalue'][5]['varvalue'] == ip:
                id = jst[x]['varvalue'][0]['varvalue']

    if not id == "no":
        if protocol == "tcp":
            rid="no"
            count=0
            for x in range(0, len(jst)):
                if jst[x]['varid'] == "addtcpredirect":
                    if jst[x]['varvalue'][1]['varvalue']==pport and jst[x]['varvalue'][5]['varvalue']==id:
                        rid=jst[x]['varvalue'][0]['varvalue']
                    count=count+1
            pdata = {
               'tcpredirect_id['+str(count)+']': rid,
                'tcpredirect_id_deleteEntry['+str(count)+']':'delete',
                'csrf_token':csrf
            }
            ppr = requests.post(url=url + "/data/Portforwarding.json?lang=de", headers=headers,cookies=session_c, data=pdata, verify=False, allow_redirects=True)
            jsre = json.loads(ppr.text)
            if jsre[2]['varvalue']['MultiDatabaseSink_0'][0]['varvalue'][1]['varvalue'] == "ok":
                print(bcol.lgreen + "[+]Port redirect successfully deleted!" + bcol.reset)
            else:
                print(bcol.red + "[-]Port deleting failed" + bcol.reset)
        elif protocol == "udp":
            rid = "no"
            count = 0
            for x in range(0, len(jst)):
                if jst[x]['varid'] == "addudpredirect":
                    if jst[x]['varvalue'][1]['varvalue'] == pport and jst[x]['varvalue'][5]['varvalue'] == id:
                        rid = jst[x]['varvalue'][0]['varvalue']
                    count = count + 1
            pdata = {
                'udpredirect_id[' + str(count) + ']': rid,
                'udpredirect_id_deleteEntry[' + str(count) + ']': 'delete',
                'csrf_token': csrf
            }
            ppr = requests.post(url=url + "/data/Portforwarding.json?lang=de", headers=headers, cookies=session_c, data=pdata, verify=False, allow_redirects=True)
            jsre = json.loads(ppr.text)
            if jsre[2]['varvalue']['MultiDatabaseSink_0'][0]['varvalue'][1]['varvalue'] == "ok":
                print(bcol.lgreen + "[+]Port redirect successfully deleted!" + bcol.reset)
            else:
                print(bcol.red + "[-]Port deleting failed" + bcol.reset)
    else:
        print(bcol.red + "[-]No device with specified IP found!" + bcol.reset)

def listPortRedirects(session_c,csrf):
    global headers
    global purl
    global p
    global url
    pr = requests.get(url=url + "/data/Portforwarding.json", headers=headers, cookies=session_c, verify=False, allow_redirects=True)
    jst=json.loads(pr.text)
    c=1
    for x in range(0, len(jst)):
        if jst[x]['varid'] == "dynrule_addmdevice":
            c=c+1
    dev=[[0 for x in range(3)] for y in range(c)]
    #id,name,ip
    co=0
    for x in range(0, len(jst)):
        if jst[x]['varid'] == "dynrule_addmdevice":
            dev[co][0]=jst[x]['varvalue'][0]['varvalue']
            dev[co][1] = jst[x]['varvalue'][1]['varvalue']
            dev[co][2] = jst[x]['varvalue'][5]['varvalue']
            co=co+1

    pubfp = []
    pubtp = []
    intp = []
    act = []
    devid = []
    for x in range(0, len(jst)):
        if jst[x]['varid'] == "addtcpredirect":
            pubfp.append(jst[x]['varvalue'][1]['varvalue'])
            pubtp.append(jst[x]['varvalue'][2]['varvalue'])
            intp.append(jst[x]['varvalue'][3]['varvalue'])
            act.append(jst[x]['varvalue'][4]['varvalue'])
            devid.append(jst[x]['varvalue'][5]['varvalue'])

    print(bcol.dblue+"TCP Redirects:"+bcol.reset)
    for x in range(0, len(act)):
        devname=""
        devip=""
        for i in range(0,len(dev)):
            if dev[i][0]==devid[x]:
                devname=dev[i][1]
                devip=dev[i][2]
        print("Public port(s) "+pubfp[x]+" - "+pubtp[x]+" to "+devname+"("+devip+") Port: "+intp[x]+" Active: "+act[x])

    pubfp = []
    pubtp = []
    intp = []
    act = []
    devid = []
    for x in range(0, len(jst)):
        if jst[x]['varid'] == "addudpredirect":
            pubfp.append(jst[x]['varvalue'][1]['varvalue'])
            pubtp.append(jst[x]['varvalue'][2]['varvalue'])
            intp.append(jst[x]['varvalue'][3]['varvalue'])
            act.append(jst[x]['varvalue'][4]['varvalue'])
            devid.append(jst[x]['varvalue'][5]['varvalue'])

    print("\n"+bcol.lgreen+"UDP Redirects:"+bcol.reset)
    for x in range(0, len(act)):
        devname = ""
        devip = ""
        for i in range(0, len(dev)):
            if dev[i][0] == devid[x]:
                devname = dev[i][1]
                devip = dev[i][2]
        print("Public port(s) " + pubfp[x] + " - " + pubtp[x] + " to " + devname + "(" + devip + ") Port: " + intp[x] + " Active: " + act[x])

def setWifiState(state,session_c,csrf):
    global headers
    global purl
    global p
    global url
    pdata = {
        'use_wlan': state,
        'csrf_token': csrf
    }
    pdata5 = {
        'use_wlan_5ghz': state,
        'csrf_token': csrf
    }
    requests.post(url=url + "/data/Modules.json?lang=de", headers=headers, cookies=session_c, data=pdata, verify=False, allow_redirects=True)
    swr5 = requests.post(url=url + "/data/Modules.json?lang=de", headers=headers, cookies=session_c, data=pdata5, verify=False, allow_redirects=True)
    rej=json.loads(swr5.text[:-6]+"]")
    if rej[12]['varvalue']==state and rej[13]['varvalue']==state:
        if state=="0":
            print(bcol.lgreen+"[+]Wifi is disabled!"+bcol.reset)
        elif state=="1":
            print(bcol.lgreen+"[+]Wifi is enabled!"+bcol.reset)
    else:
        if state == "0":
            print(bcol.red + "[-] Error! Wifi can't be disabled!" + bcol.reset)
        elif state == "1":
            print(bcol.red + "[-] Error! Wifi can't be enabled!" + bcol.reset)

def setWifiAcessLimit(session_c,dev_mac,csrf,disable):
    global headers
    global purl
    global p
    global url
    re=requests.get(url=url + "/data/WLANAccess.json", headers=headers, cookies=session_c, verify=False, allow_redirects=True)
    pos=re.text.rfind("\"varid\":\"mdevice_name_configing\",")
    sec=False
    for x in range(pos,0,-1):
        print(re.text[x])
        if re.text[x:x+1]=="}":
            if re.text[x+1:x+2]==",":
                if sec:
                    pos=x+1
                    break
                sec=True
    try:
        js=json.loads(re.text[0:pos]+re.text[pos+1:])
    except json.JSONDecodeError as e:
        print(re.text[8534:]+"\n"+str(e))
    dev=[]
    for x in range(0,len(js)):
        if js[x]["varid"]=="wlan_addmdevice":
            dev.append([js[x]["varvalue"][0]["varvalue"],js[x]["varvalue"][2]["varvalue"]])
    print(dev)
    found=False
    if not disable:
        for device in dev:
            if device[1]==dev_mac:
                found=True
                break
    if found or disable:
        data={
           "csrf_token": csrf,
        }
        if disable:
            data["wlan_allow_all"] = 0
            for x in range(0,len(dev)):
                data["sid[" + str(x + 1) + "]"] = dev[x][0]
        else:
            data["wlan_allow_all"] =1
            for x in range(0,len(dev)):
                if dev[x][1]==dev_mac:
                    data["mdevice_name["+str(x+1)+"1]"]=0
                else:
                    data["mdevice_name[" + str(x + 1) + "1]"] = 1
                data["sid[" + str(x + 1) + "1]"] = dev[x][0]
        re=requests.post(url=url + "/data/WLANAccess.json", headers=headers, cookies=session_c, data=data, verify=False, allow_redirects=True)
        if json.loads(re.text)[0]["varvalue"]=="ok":
            if disable:
                print(bcol.lgreen + "[+] Access limit deactivated!" + bcol.reset)
            else:
                print(bcol.lgreen+"[+] Device succesfully blocked!"+bcol.reset)
        else:
            print(bcol.red + "[-] Something went wrong!" + bcol.reset)
    else:
        print(bcol.red+"[-] Specified Mac address not found in device list!"+bcol.reset)

def main():
    p=argparse.ArgumentParser(description="Speedport W 724V Type A - cmd configuration by Tobias Bittner (C) 2019/20\t"+bcol.red+"\nIf you use this tool every session logged into the router will be closed!"+bcol.dblue+"\nNew features available soon!"+bcol.reset,formatter_class=RawTextHelpFormatter)
    p.add_argument('-version',action="version",version='0.0.2 pre-alpha')
    p.add_argument('-pw',default=argparse.SUPPRESS,help="Sets your Speedport password to use this tool.",metavar="speedport_password",nargs=1,required=True)
    p.add_argument('-abl',default=argparse.SUPPRESS,help="Adds an internet blocker for a device",metavar=("blocker_name", "ip_of_device"),nargs=2)
    p.add_argument('-dbl', default=argparse.SUPPRESS,help="Deletes an internet blocker",metavar="blocker_name",nargs=1)
    p.add_argument('-apr', default=argparse.SUPPRESS,help="Adds a port forwarding rule",metavar=("public_port", "device_port","protocol_tcp_or_udp","device_ip"),nargs=4)
    p.add_argument('-dpr', default=argparse.SUPPRESS, help="Deletes a port forwarding rule", metavar=("public_port", "protocol_tcp_or_udp", "device_ip"), nargs=3)
    p.add_argument('-lpr', default=argparse.SUPPRESS, help="Lists all port redirect rules", action="store_false")
    p.add_argument('-enw', default=argparse.SUPPRESS, help="Enables Wifi (2.4 and 5 GHz)", action="store_false")
    p.add_argument('-diw', default=argparse.SUPPRESS, help="Disables Wifi (2.4 and 5 GHz)", action="store_false")
    p.add_argument('-wial', default=argparse.SUPPRESS, help="wial e 00:00:00:00:00:00 to enable (e) Wifi access limit and exclude device with given mac address from the wifi network\n"
                                                            "wial d type_sth_random to disable wifi access limit", metavar="device_mac", nargs=2)
    args=p.parse_args()

    if hasattr(args,"pw"):
        pw=args.pw[0]
        if hasattr(args,"abl"):
            if len(args.abl[1].split(".")) == 4:
                session = login(pw)
                csrf = getCsrf(session)
                print("Csrf Token: " + csrf)
                blockTraffic(args.abl[1], csrf, session, args.abl[0])
            else:
                print(bcol.red + "[-]Please enter a valid IP!" + bcol.reset)
        elif hasattr(args,"dbl"):
            session = login(pw)
            csrf = getCsrf(session)
            print("Csrf Token: " + csrf)
            deleteBlocker(args.dbl[0], session, csrf)
        elif hasattr(args,"apr"):
            if len(args.apr[3].split(".")) == 4:
                session = login(pw)
                csrf = getCsrf(session)
                print("Csrf Token: " + csrf)
                addPortForward(args.apr[0], args.apr[1], args.apr[2], args.apr[3], session, csrf)
            else:
                print(bcol.red + "[-]Please enter a valid IP!" + bcol.reset)
        elif hasattr(args, "dpr"):
            if len(args.apr[2].split(".")) == 4:
                session = login(pw)
                csrf = getCsrf(session)
                print("Csrf Token: " + csrf)
                deletePortForward(args.apr[0], args.apr[1], args.apr[2], session, csrf)
            else:
                print(bcol.red + "[-]Please enter a valid IP!" + bcol.reset)
        elif hasattr(args, "lpr"):
            session = login(pw)
            csrf = getCsrf(session)
            print("Csrf Token: " + csrf)
            listPortRedirects(session,csrf)
        elif hasattr(args, "enw"):
            session = login(pw)
            csrf = getCsrf(session)
            print("Csrf Token: " + csrf)
            setWifiState("1",session,csrf)
        elif hasattr(args, "diw"):
            session = login(pw)
            csrf = getCsrf(session)
            print("Csrf Token: " + csrf)
            setWifiState("0",session,csrf)
        elif hasattr(args, "wial"):
            session = login(pw)
            csrf = getCsrf(session)
            print("Csrf Token: " + csrf)
            if args.wial[0]=="e":
                setWifiAcessLimit(session,args.wial[1].upper(),csrf,False)
            elif args.wial[0]=="d":
                setWifiAcessLimit(session, "not", csrf,True)

    else:
        print(bcol.red + "[-]Set a password!" + bcol.reset)


def mainn():
    session = login("842wlan321")
    csrf = getCsrf(session)
    print("Csrf Token: " + csrf)
    #deletePortForward("2557","udp","192.168.2.248",session,csrf)
    #setWifiState("1",session,csrf)
    forb=[80,443,8888,2222,1402,5005,25565,8,6,5006,10,25575]
    for i in range(1,51):
        for x in range(0,len(forb)):
            if i ==forb[x]:
                i=i+1;
        addPortForward(i,443,"tcp","192.168.2.148",session,csrf)

if __name__ == "__main__": main()