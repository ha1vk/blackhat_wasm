#coding:utf8
import re

f = open('./include/instruction.h','r')
content = f.read()
f.close()

classes = re.findall(r'class (.*?) :',content,re.S|re.M)

template = 'ADD_SINSTRUCTION_LIST({})'
for clazz in classes:
   clazz = clazz.strip()
   inst = template.format(clazz)
   print inst