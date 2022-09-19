import pyshark
import json

# load pcap file
cap = pyshark.FileCapture('team13-service4-2022_09_15-09_02_44.pcap',display_filter = 'http.request.method')

information = list()

for pkt in cap:
    try:
        # only dump http requests
        if pkt.http.request_method:
            # extract cookies
            cookies = {pkt.http.cookie.split("=",1)[0]: pkt.http.cookie.split("=",1)[1]}

            url = pkt.http.request_full_uri.split("//")[1]
            # append http method, url, user agent, cookies 
            information.append({"method":     pkt.http.request_method,
                                "destination": url.split("/",1)[0],
                                "url":        "/"+url.split("/",1)[1],
                                "user_agent": pkt.http.user_agent,
                                "cookies":    cookies})

    except:
        pass
        
json_object = json.dumps(information, indent = 4) 
print(json_object)