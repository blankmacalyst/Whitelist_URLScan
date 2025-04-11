import requests
import os
import time
import json
#virus total api scan
vtapi = os.getenv("VT_API")
hybridapi = os.getenv("HYBRID_API")
if vtapi == None:
    print("API variable not found")
    exit()
#vtapi = os.getenv('VT_API')
url_to_scan = input("Enter URL to scan: ")
params = {'apikey' : vtapi, 'url' : url_to_scan}
scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
response = requests.post(scan_url, data=params)
if response.status_code == 200:
    data=response.json()
    print(response.json())
    scan_id = data['scan_id']
else:
    print("Error scanning url, please make sure it is correct")
    exit()
time.sleep(20)
params = {'apikey' : vtapi, 'resource' : scan_id}
report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
response = requests.get(report_url, params=params)
if response.status_code == 200:
    vt_response_data = response.json()
    nice_vt_response_data = json.dumps(vt_response_data, indent=4)
    print(nice_vt_response_data)

#hybrid analysis scan
hybrid_scan_url = 'https://www.hybrid-analysis.com/api/v2/quick-scan/url'
headers = {
    'accept' : 'application/json',
    'api-key' : hybridapi,
    'Content-Type' : 'application/x-www-form-urlencoded'
}
data = {
    'scan_type' : 'all',
    'url' : url_to_scan,
    'no_share_third_party' : 'true',
    'allow_community_access' : 'false',
    'comment' : '',
    'submit_name' : ''
}
response = requests.post(hybrid_scan_url, headers=headers, data=data)
if response.status_code == 200:
    print(response.json())
    hybrid_data = response.json()
    hybird_scan_id = hybrid_data['id']
else:
    print("Error running hybrid scan please check and retry")
    exit()
time.sleep(20)
hybrid_request_url=f'https://hybrid-analysis.com/api/v2/quick-scan/{hybird_scan_id}'
request_headers={
    'accept' : 'application/json',
    'api-key' : hybridapi
}
response = requests.get(hybrid_request_url, headers=request_headers)
if response.status_code == 200:
    hybrid_response_data = response.json()
    nice_hybrid_output = json.dumps(hybrid_response_data, indent=4)
    print(nice_hybrid_output)
else:
    print("Error obtaining scan results from Hybrid, please check and try again")
for scanner, status_data in hybrid_response_data["scanners_v2"].items():
    status = status_data.get("status")
if status in ["suspicious", "malicious"]:
    print(f'The status of {scanner} is suspicious or malicious, status : {status}')

