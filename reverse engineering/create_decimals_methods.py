address = 0

while 1:
	if idc.isCode(idc.GetFlags(address)):
		print "Code", address
	elif idc.isData(idc.GetFlags(address)):
		print "Data", address
	elif idc.isTail(idc.GetFlags(address)):
		print "Tail", address
	elif idc.isHead(idc.GetFlags(address)):
		print "Head", address
	elif idc.isUnknown(idc.GetFlags(address)):
		print "Unknown", address

	else:
		break

	address = address + 1



### faster approach

address = 0
if idc.isCode(idc.GetFlags(address)):
		print address

while 1:
	prev_addr = address
	address = idc.FindCode(address, SEARCH_DOWN | SEARCH_NEXT)
	if address == prev_addr:
		break
	else:
		print address


### hybrid approach - combined - using this one
file = open("combined.txt","w")
all_segments = []
for s in idautils.Segments():
	all_segments.append([s,idc.SegName(s)])
i = 0
selected = ['.init','.plt','.text','.fini','.init_array','.fini_array','.jcr','.got','.data']
segments = []
while i<(len(all_segments)-1):
	if all_segments[i][1] in selected:
		segments.append([all_segments[i][0],all_segments[i+1][0]])
	i = i + 1


string = "address,type,disassembly,bytes"
for segment in segments:
	for address in range(segment[0],segment[1]):
		if idc.isCode(idc.GetFlags(address)):
			string = string + "\n"
			file.write(string) 
			string = str(address) + ",code," + idc.GetDisasm(address) + "," + str(idc.Byte(address)) 
		elif idc.isData(idc.GetFlags(address)):
			string = string + "\n"
			file.write(string)
			print string
			string = str(address) + ",data," + idc.GetDisasm(address) + "," + str(idc.Byte(address)) 
		elif idc.isTail(idc.GetFlags(address)):
			string = string + "-" + str(idc.Byte(address))

file.close()

### hybrid approach - code

address = 0
file = open("sample.txt", "w")
if idc.isCode(idc.GetFlags(address)):
		print address, "code", idc.GetDisasm(address), idc.Byte(address)
		file.write(str(address) + ",code," + idc.GetDisasm(address) + "," +  str(idc.Byte(address)) + "\n")
		trail_address = address + 1
		while idc.isTail(idc.GetFlags(trail_address)):
			print trail_address, "tail", idc.GetDisasm(trail_address), idc.Byte(trail_address)
			file.write(str(trail_address) + ",tail," + idc.GetDisasm(trail_address) + "," +  str(idc.Byte(trail_address)) + "\n")
			trail_address = trail_address + 1

while 1:
	prev_addr = address
	address = idc.FindCode(address, SEARCH_DOWN | SEARCH_NEXT)
	if address == prev_addr:
		break
	else:
		print address, "code", idc.GetDisasm(address), idc.Byte(address)
		file.write(str(address) + ",code," + idc.GetDisasm(address) + "," +  str(idc.Byte(address)) + "\n")
		trail_address = address + 1
		while idc.isTail(idc.GetFlags(trail_address)):
			print trail_address, "tail", idc.GetDisasm(trail_address), idc.Byte(trail_address)
			file.write(str(trail_address) + ",tail," + idc.GetDisasm(trail_address) + "," +  str(idc.Byte(trail_address)) + "\n")
			trail_address = trail_address + 1

file.close()

### hybrid approach - data

address = 0
file = open("sample-data.txt", "w")
if idc.isData(idc.GetFlags(address)):
		print address, "data", idc.GetDisasm(address), idc.Byte(address)
		file.write(str(address) + ",data," + idc.GetDisasm(address) + "," +  str(idc.Byte(address)) + "\n")
		trail_address = address + 1
		while idc.isTail(idc.GetFlags(trail_address)):
			print trail_address, "tail", idc.GetDisasm(trail_address), idc.Byte(trail_address)
			file.write(str(trail_address) + ",tail," + idc.GetDisasm(trail_address) + "," +  str(idc.Byte(trail_address)) + "\n")
			trail_address = trail_address + 1

while 1:
	prev_addr = address
	address = idc.FindData(address, SEARCH_DOWN | SEARCH_NEXT)
	if address == prev_addr:
		break
	else:
		print address, "data", idc.GetDisasm(address), idc.Byte(address)
		file.write(str(address) + ",data," + idc.GetDisasm(address) + "," +  str(idc.Byte(address)) + "\n")
		trail_address = address + 1
		while idc.isTail(idc.GetFlags(trail_address)):
			print trail_address, "tail", idc.GetDisasm(trail_address), idc.Byte(trail_address)
			file.write(str(trail_address) + ",tail," + idc.GetDisasm(trail_address) + "," +  str(idc.Byte(trail_address)) + "\n")
			trail_address = trail_address + 1

file.close()

### writing addresses

file = open("MyFile.txt", "w")

address = 0

while 1:
	if idc.isCode(idc.GetFlags(address)):
		file.write("Code " + str(address))
	elif idc.isData(idc.GetFlags(address)):
		file.write("Data " + str(address))
	elif idc.isTail(idc.GetFlags(address)):
		file.write("Tail " + str(address))
	elif idc.isHead(idc.GetFlags(address)):
		file.write("Head " + str(address))
	elif idc.isUnknown(idc.GetFlags(address)):
		file.write("Unknown " + str(address))

	else:
		break

	address = address + 1

file.close()



### batch file generation

import os
import subprocess
import glob
paths = glob.glob("*")
ida_path = os.path.join(os.environ['PROGRAMFILES'], "IDA", "idat.exe")
for file_path in paths:
	if file_path.endswith(".py"):
 		continue

	subprocess.call([ida_path, "-B", file_path])


### running script on file

import idc
import idaapi
import idautils
idaapi.autoWait()
count = 0
for func in idautils.Functions():
 # Ignore Library Code
	flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
	if flags & FUNC_LIB:
		continue
	for instru in idautils.FuncItems(func):
		count += 1
f = open("instru_count.txt", 'w')
print_me = "Instruction Count is %d" % (count)
f.write(print_me)
f.close()
idc.Exit(0)