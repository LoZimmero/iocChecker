import os

names = os.listdir('preparedSept2022')
for i in range(0,16):
    name = names[i]
    os.system(f'python IoCcheck.py -i my.ini -f preparedSept2022\\part{i}.csv')