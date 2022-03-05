###########################################################

# This script is developed by Mohab El-Banna (Mouhab-dev)
# Version 1.0 (17/1/2022)
# Follow me on Github for more work: github.com/mouhab-dev

###########################################################

import requests
import requests.auth
from getpass import getpass
import json
import time

# TODO
# 1) analyze only if the file was not detected as malicious  (DONE)
# 2) Handle no results found for a hash                      (DONE)
# 3) Elapsed Time                                            (DONE)
# 4) Deal with analysis result when missing security engine: (Testing...)
# throws KeyError Exception                                  (Testing...)
# or: result is timeout                                      (Testing...)



user = input('Enter Your Username: ')#TODO To be removed when published
passwd = getpass('Enter your Password: ')#TODO To be removed when published
print()
count = 1

av_engine_1=''#TODO Enter your 1st Anti Virus Engine
av_engine_2=''#TODO Enter your 2nd Anti Virus Engine

proxies = { 
    "http"  : 'http://'+user+':'+passwd+'@proxy_ip:port' 
    } # Ignore if you won't use proxy

headers = {
    "Accept": "application/json",
    "x-apikey": "", #TODO Write your API KEY
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
}


def View_file_report(hash):
    response = requests.get(f'http://www.virustotal.com/api/v3/files/{hash}', headers=headers, proxies=proxies) #Remove proxies=proxies if you won't use proxy
    if response.status_code == 200:
        return json.loads(response.text)
    elif response.status_code == 404:
        return 404


def Reanalyze_file(hash):
    # Post the hash for re-analysis on VT
    response = requests.post(f'http://www.virustotal.com/api/v3/files/{hash}/analyse', headers=headers, proxies=proxies) #Remove proxies=proxies if you won't use proxy
    print('Re-Analyzing ...')
    if response.status_code == 407:
        print('''Reply From Proxy Server:
        Your credentials could not be authenticated: "Credentials are missing.".
        You will not be permitted access until your credentials can be verified.''')
        exit(1)
        # print(response.status_code)
        # print(response.text)
    elif response.status_code == 429:
        print('''[Error]: QuotaExceededError | You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.
        You may have run out of disk space and/or number of files on your VirusTotal Monitor account.''')
        exit(1)
    elif response.status_code == 200:
        return json.loads(response.text)['data']['id']


def Get_analysis_report(analysis_id):
    # Check for re-analysis status and result
    get_result = requests.get(f'http://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers, proxies=proxies) #Remove proxies=proxies if you won't use proxy
    global count 
    # print(get_result.text)
    # print(get_result.status_code)

    if get_result.status_code == 200 :
        get_result_json = json.loads(get_result.text)

        if get_result_json['data']['attributes']['status'] == 'completed': #queued
            return json.loads(get_result.text)
        else:
            time.sleep(15)
            m, s = divmod(15*count, 60)
            h, m = divmod(m, 60)
            print(f'Waiting for Re-Analysis Result | Elapsed Time: {h:02d}:{m:02d}:{s:02d}', end='\r')
            count += 1 
            return Get_analysis_report(analysis_id) # Should put return to avoid returning NONE
    else:
        print(get_result.status_code)
        print(get_result.text)
        exit(1)


def Get_analysis_status(analysis_id):
    get_result = requests.get(f'http://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers, proxies=proxies) #Remove proxies=proxies if you won't use proxy

    if get_result.status_code == 200:
        get_result_json = json.loads(get_result.text)
        if get_result_json['data']['attributes']['status'] == 'completed': #queued
            return 'completed'
        else:
            time.sleep(15)
            return Get_analysis_status(analysis_id) # Should put return to avoid returning NONE


def Extract_report_values(report_json):
        # Extract SHA256 and MD5 Hashes
        sha256_hash = report_json['meta']['file_info']['sha256']
        md5_hash = report_json['meta']['file_info']['md5']
        av_engine_1_res, av_engine_2_res = '',''
        # Extract both AV results
        try:
            av_engine_1_res = report_json['data']['attributes']['results']['{}'.format(av_engine_1)]['category']
            av_engine_2_res = report_json['data']['attributes']['results']['{}'.format(av_engine_2)]['category']
        except KeyError:
            print("[!] Couldn't find security engine in analysis result.")

        return sha256_hash, md5_hash, av_engine_1_res, av_engine_2_res


# Read hashes from txt File
with open('hashes.txt','r',encoding='utf-8-sig') as input_file: # added utf-8-sig to avoid reading unicode chars
    with open('hashes_result.txt', 'w') as output_file:
        for hash in input_file:
            hash = hash.strip('\n').strip()  # added .strip() to remove any leading and trailling whitspaces
            hash_len = len(hash)
            print('[*] Currently under check: ',hash)
            if hash_len != 32 and hash_len != 40 and hash_len != 64 :
                print('[!] Wrong Hash Length, Please check hash values again.')
            else:
                report_n_json = View_file_report(hash)
            
                if report_n_json == 404: # Check for a file hash that has not been submitted yet
                    print("[+] No matches found.")
                    output_file.write(f'{hash}\n')
                else:
                    av_engine_1_result, av_engine_2_result = '',''
                    try: # Extract both AV's values
                        av_engine_1_result = report_n_json['data']['attributes']['last_analysis_results']['{}'.format(av_engine_1)]['category']
                        av_engine_2_result = report_n_json['data']['attributes']['last_analysis_results']['{}'.format(av_engine_2)]['category']
                    except KeyError: # This exception is raised if any av engine was not found.
                        print("[!] Couldn't find security engine in analysis result.")
                        pass # Ignore error if engine results were not found as it will be reanalyzed below.

                    Done = False
                    while (not Done):
                        # if both engines have detected file hash
                        if av_engine_1_result == 'malicious' and av_engine_2_result == 'malicious': 
                            print('[*] Detected by both AV engines.')
                            break

                        analysis_id = Reanalyze_file(hash)
                        report_n_json = Get_analysis_report(analysis_id)
                        count = 1 # Reset Time after analysis finishes
                        print()
                        sha256_h, md5_h, av_engine_1_result, av_engine_2_result = Extract_report_values(report_n_json)

                        # if any enigne has timeout Result
                        if av_engine_1_result == 'timeout' or av_engine_2_result == 'timeout':
                            print("[!] One of the AV engines has timeout.")
                            # time.sleep(300)
                            # continue
                        # If any eninge was not found among results
                        elif av_engine_1_result == '' or av_engine_2_result == '':
                            # time.sleep(300)
                            # continue
                            pass

                        if av_engine_1_result == 'undetected' :
                            # Write sha256 to output_file
                            output_file.write(f'{sha256_h}\n')
                            print('[+] {} Result: '.format(av_engine_1), av_engine_1_result+' | '+sha256_h)
                            Done = True

                        if av_engine_2_result == 'undetected' :
                            # Write md5 to output_file
                            output_file.write(f'{md5_h}\n')
                            print('[+] {} Result: '.format(av_engine_2),av_engine_2_result+' | '+md5_h)
                            Done = True

            print('---------------------------------------')           
             
