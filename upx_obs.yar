rule UPX_p_info_obfuscation {
 strings:
    $upx_magic_with_zero_sizes = {
      55 50 58 21
      ?? ?? ?? ?? ?? ?? ?? ??
      00 00 00 00 00 00 00 00
    }
  condition:
    all of them
}
