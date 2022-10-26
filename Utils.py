from datetime import datetime
import os
from OTXv2 import OTXv2
import IndicatorTypes
from malwarebazaar.api import Bazaar
import json
from pymisp import PyMISP
import subprocess
import requests
import time


# generate result file
def generateResultFilename(inputFileName):
    resultFile = ("check-results_{0}"+"_"+os.path.splitext(os.path.basename(inputFileName))[0]+os.path.splitext(os.path.basename(inputFileName))[1]).format(datetime.now().strftime("%Y-%m-%d"))
    #resultFile = "check-results_{0}.csv".format(os.path.splitext(os.path.basename(inputFileName))[0])
    return resultFile

#get access into indicator_details for ALien Vault
def get_indicator_details(alienkey,type,indic):
    try:
        otx = OTXv2(alienkey)
        time.sleep(5)
        indicator_details = otx.get_indicator_details_full(type, indic)

        # misp_attributes = misp.search(attribute,indic)
        return indicator_details
    except Exception as e:
        print(e)
        #print(indic)
#get access to malwareBazaar hash db
def get_Bazaarhash_details (bazarkey,type,indic):
    bazaar_apikey = Bazaar(bazarkey)
    time.sleep(5)
    bazarresponse = bazaar_apikey.query_hash(indic)
    return bazarresponse

#get access to Misp db

def get_misp_connect (misp_url,misp_key):

    misp = PyMISP(misp_url, misp_key, ssl=False)
    #mispresponse = misp.search(controller='attributes', value='value')
    return misp

# opentip kaspersky
def get_indicator_kasper(type,value,key_list):
    
    time.sleep(5)
    result = None
    url = 'https://opentip.kaspersky.com/api/v1/search/' + type + '?request='+ value+' '
    c=0
    for key in key_list:
        c+=1
        try:
            res = requests.get(url, headers={'x-api-key': key})
            if res.status_code == 200 and res.json():
                result = res.json()
                print('using kaspersky key n.'+c+' out of '+len(key_list))
                break
        except Exception as e:
            print(e)
    return result


# urlhaus

def query_urlhaus_url(indicator):
    # Construct the HTTP request
    data_url = {'url' : indicator}
    #url
    time.sleep(5)
    response_url = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data_url)
    #hash
    # Parse the response from the API
    json_response_url = response_url.json()
    return json_response_url

def query_urlhaus_hash(indicator):
    data_hash = {'hash': indicator}
    time.sleep(5)
    response_hash = requests.post('https://urlhaus-api.abuse.ch/v1/payload/', data_hash)
    json_response_hash = response_hash.json()
    return json_response_hash

def query_urlhaus_host(indicator):
    data_host = {'host': indicator}
    time.sleep(5)
    response_host = requests.post('https://urlhaus-api.abuse.ch/v1/host/', data_host)
    json_response_host = response_host.json()
    return json_response_host

# Virus Total
def get_indicator_vt(type,value,key_list):
    
    url = 'https://www.virustotal.com/api/v3/search?query=' + value
    time.sleep(5)
    c=0
    result = None
    for key in key_list:
        c+=1
        try:
            res = requests.get(url, headers={'X-Apikey': key})
            if res.status_code == 200 and res.json():
                result = res.json()
                print('using VirusTotal key n.'+c+' out of '+len(key_list))
                break
        except Exception as e:
            print(e)
    return result


def get_hashlookup(lookupurl,hashtype,value):
    url = lookupurl+hashtype+'/'+ value
    #print(url)
    try:
        time.sleep(5)
        result = requests.get(url).json()
    except Exception as e:
        print(e)
    return result
