rule powercrypter_crypted_executable {

  meta:
    author = "Chad Baxter"
    author_email = "cbaxter@mail.umw.edu"
    date = "2020-04-29"
    updated = "2020-04-29"
    description = "PowerCrypter encrypted executable (possible malware)"

  strings:
    $script = "CRYPTE~1.PS1" ascii wide
    $win_pack0 = "wextract" ascii wide nocase
    $win_pack1 = "Win32 Cabinet Self-Extractor" ascii wide
    $launcher = "exec.bat" ascii wide

  condition:
    all of them

}
