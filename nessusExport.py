import requests
import json
import argparse


u = ""
accessKey = ""
secretKey = ""

header = {

}



def get_scan_list():




    url = f"{u}scans"

    response = requests.get(url, headers=header, verify=False)
    if response.status_code == 200:
        result = json.loads(response.text)
        return result


# 获取下载token
def get_download_csv_token(id):
    global token
    url = f"{u}scans/{id}/export?limit=10000"


    data = {'format':'csv',
             'template_id':'',
             'reportContents':{'csvColumns':{'id':True,'cve':True,'cvss':True,'risk':True,'hostname':True,'protocol':True,'port':True,'plugin_name':True,'synopsis':True,'description':True,'solution':True,'see_also':True,'plugin_output':True,'stig_severity':False,'cvss3_base_score':False,'cvss_temporal_score':False,'cvss3_temporal_score':False,'risk_factor':False,'references':False,'plugin_information':False,'exploitable_with':False}},
             'extraFilters':{'host_ids':[],'plugin_ids':[]}}
    response = requests.post(url, data=json.dumps(data), headers=header, verify=False)
    if response.status_code == 200:
        data = json.loads(response.text)
        token = data["token"]
        return token

# 下载文件
def downloadfile(token, filename):

    # 下载处理
    downloadurl = f"{u}tokens/{token}/download"

    r = requests.get(downloadurl, stream=True, verify=False)

    with open("./{filename}.csv", "wb") as f:
        for chunk in r.iter_content(chunk_size=512):
            f.write(chunk)


# 拿到scans的id
def getScanId():
    url = f"{u}scans?"
    response = requests.get(url, headers=header, verify=False)
    if response.status_code == 200:
        data = json.loads(response.text)
        return data



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u')
    parser.add_argument('-ak')
    parser.add_argument('-sk')

    args = parser.parse_args()
    u = args.u
    accessKey = args.ak
    secretKey = args.sk

    header = {
        'X-ApiKeys': 'accessKey={accesskey};secretKey={secretkey}'.format(accesskey=accessKey, secretkey=secretKey),
        "Content-Type": "application/json"
    }



    csvId = getScanId()
    print(len(csvId["scans"]))
    for i in range(len(csvId["scans"])):
        id = csvId["scans"][i]["id"]
        filename = csvId["scans"][i]["name"]
        token = get_download_csv_token(id)
        downloadfile(token, filename)