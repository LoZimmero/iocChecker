import subprocess
import time

import requests

import Utils


def main():


    key='errvRiZ6Q0e+hCE3Um3aYw=='
    key_list=[]
    key_list.append(key)
    key_list.append("bTWlGAWITAKR6mv6Ctozsg==")
    Utils.get_indicator_kasper('ip','149.28.147.15',key_list)

if __name__ == '__main__':
   main()
