import subprocess
import os
path = 'C:\\Users\\user\\Downloads\\armhf\\'
python_file = 'C:\\Users\\user\\Downloads\\create_decimals.py'
arr = os.listdir(path)

total = len(arr)
count = 0
for file in arr:
	if file.endswith('.code') or file.endswith('.idb'):
		count = count + 1
		print(count,"/",total, "skipped")
		continue

	if (file+'.idb') in arr:
		count = count + 1
		print(count,"/",total, "skipped, already outputted")
		continue
	if os.stat(path+file).st_size>200000:
		count = count + 1
		print(count,"/",total, "skipped, greatter than 200kb")
		continue

	print(file)
	command = "ida -A -S" + python_file + " " + path + file
	p = subprocess.Popen(command)
	p.communicate()
	count = count + 1
	print(count,"/",total)

