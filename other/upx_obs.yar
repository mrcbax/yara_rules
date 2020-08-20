rule UPX_p_info_obfuscation {
  meta:
    retrieved_from = "https://blag.nullteilerfrei.de/2019/12/26/upx-packed-elf-binaries-of-the-peer-to-peer-botnet-family-mozi/"
  strings:
    $upx_magic_with_zero_sizes = {
      55 50 58 21
      ?? ?? ?? ?? ?? ?? ?? ??
      00 00 00 00 00 00 00 00
    }
  condition:
    all of them
}
