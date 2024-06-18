import psutil

print(psutil.cpu_times())

for x in range(3):
    psutil.cpu_percent(interval=1)