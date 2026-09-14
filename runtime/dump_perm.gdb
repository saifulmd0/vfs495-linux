set pagination off
set confirm off
break *0x46f510
commands 1
  silent
  set $cfg = (char*)$rcx
  set $w = *(int*)($cfg+4)
  set $scale = *(int*)$cfg
  printf "HIT UnpackLineRT: width=%d cfg[0]=%d line[6]&0xf=%d\n", $w, $scale, (*(unsigned char*)($rdi+6))&0xf
  eval "dump binary memory ./captures/perm.bin $cfg+0x57c $cfg+0x57c+%d", $w*2
  eval "dump binary memory ./captures/bitlen.bin $cfg+8 $cfg+8+%d", $w
  printf "dumped perm (%d int16) + bitlen (%d)\n", $w, $w
  detach
  quit
end
run getprintwait -doinit
quit
