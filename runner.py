import os

names = os.listdir('preparedSept2022')
for i in range(0,1):
    name = names[i]
    print(f'Processing now file preparedSept2022/part{i}')
    os.system(f'python IoCcheck.py -i my.ini -f preparedSept2022/part{i}.csv')