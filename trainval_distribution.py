train = open('train.txt','w')
val = open('val.txt','w')
trainval = open('trainval.txt','w')

for count, file in enumerate(files):
    trainval.write(file.strip('.csv') +"\n")
    if count%2==0:
        train.write(file.strip('.csv') +"\n")
    else:
        val.write(file.strip('.csv') +"\n")
train.close()
val.close()
trainval.close()