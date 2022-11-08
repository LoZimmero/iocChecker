import os
import json

KEYS = ['indicator','indicator_type', 'label', 'user', 'twitter_link', 'alienvault_date',
'hashlookup_date', 'kaspersky_date', 'mwbazar_date', 'misp_date', 'urlhaus_date', 'virustotal_date']

def populate_date(source_json: dict, destination_json: dict, source_date_field_name: str, destination_date_field_name: str):
    try:
        destination_json[destination_date_field_name] = source_json['diff_time'][source_date_field_name]['date']
    except:
        return

# ALIEN_VAULT
def has_alienvault(souce_json: dict) -> bool:
    """
    This function determines if AlienVault returned a valid response
    """
    try:
        return type(souce_json['IOC_Status']['alienvault']) == dict
    except:
        return False

def populate_av_date(source_json: dict, destination_json: dict) -> None:
    """
    This function computes and populates date from alienVault into response
    object
    """
    populate_date(source_json, destination_json, 'alientime', 'alienvault_date')

# HASHLOOKUP
def has_hashlookup(souce_json: dict) -> bool:
    """
    This function determines if hashlookup returned a valid response
    """
    try:
        return type(souce_json['IOC_Status']['hashlookup']) == dict
    except:
        return False

#TODO: Make it work
def populate_hashlookup_date(source_json: dict, destination_json: dict) -> None:
    """
    This function computes and populates date from populate_hashlookup_date into response
    object
    """ 
    populate_date(source_json, destination_json, 'hashlooktime', 'hashlookup_date')


# KASPERSKY related functions
def has_kaspersky(souce_json: dict) -> bool:
    """This function determines if kaspersky returned a valid response
    """
    try:
        return type(souce_json['IOC_Status']['kasper']) == dict
    except:
        return False


def populate_kasper_date(source_json: dict, destination_json: dict) -> None:
    """This function computes and populates date from populate_kasper_date into response
    object
    """
    populate_date(source_json, destination_json, 'kaspertime', 'kaspersky_date')


# MALWAREBAZAR related functions
def has_mwbazar(souce_json: dict) -> bool:
    """This function determines if kaspersky returned a valid response
    """
    try:
        return type(souce_json['IOC_Status']['malwarebazaar']) == dict
    except:
        return False


def populate_mwbazar_date(source_json: dict, destination_json: dict) -> None:
    """This function computes and populates date from populate_kasper_date into response
    object
    """
    populate_date(source_json, destination_json, 'malBazaartime', 'mwbazar_date')


# MISP related functions
#TODO: Make it work
def has_misp(souce_json: dict) -> bool:
    """This function determines if MISP returned a valid response
    """
    try:
        return type(souce_json['IOC_Status']['malwarebazaar']) == dict
    except:
        return False


def populate_misp_date(source_json: dict, destination_json: dict) -> None:
    """This function computes and populates date from populate_kasper_date into response
    object
    """
    populate_date(source_json, destination_json, 'misptime', 'misp_date')

# URLHAUS
def populate_urlhaus_date(source_json: dict, destination_json: dict) -> None:
    populate_date(source_json, destination_json, 'urlhaustime', 'urlhaus_date')

# VIRUSTOTAL
def populate_virustotal_date(source_json: dict, destination_json: dict) -> None:
    populate_date(source_json, destination_json, 'virustime', 'virustotal_date')


def process_json(obj: dict) -> dict:
    """This function analyzes a single json object.
    """
    # object to return
    result_obj = {}

    # get date when twitter detected IoC
    result_obj['twitter_date'] = obj.get('date')
    # get stuff at top-level from json object because I don't know if it is
    # needed.
    result_obj['indicator'] = obj.get('indicator')
    result_obj['indicator_type'] = obj.get('indicator_type')
    result_obj['label'] = obj.get('label')
    result_obj['user'] = obj.get('user')
    result_obj['tweetter_link'] = obj.get('tweetlink')

    # if we have observed sources

    populate_av_date(obj, result_obj)
    populate_hashlookup_date(obj, result_obj)
    populate_kasper_date(obj, result_obj)
    populate_misp_date(obj, result_obj)
    populate_urlhaus_date(obj, result_obj)
    populate_virustotal_date(obj, result_obj)

    return result_obj

def json_to_csv_row(json_obj: dict, separator: str = ';;') -> str:
    """Converts from JSON to csv entry
    """
    res = ''
    for k in KEYS:
        res += json_obj.get(k) or ''
        res += separator
    
    # remove last separator character
    res = res[0:len(res)-len(separator)]
    return res

def main(source_path: str, destination_file: str):

    csv_data = []
    # MAIN
    for file in os.listdir(source_path):
        json_obj_list = json.loads(open(os.path.join('output', file)).read())
        for json_obj in json_obj_list:
            res = process_json(json_obj)
            res = json_to_csv_row(res)
            csv_data.append(res)
    
    with open(destination_file, 'w+') as f:
        # write headers
        for header in KEYS:
            f.write(header + ';;')
        f.write('\n')
        # write data
        for d in csv_data:
            f.write(d)
            f.write('\n')

if __name__=='__main__':
    source_folder_path = 'output'
    destination_file = 'result.csv'
    main(source_folder_path, destination_file)