rule flag_regex {

  meta:
    author = "Chad Baxter"
    description = "matches on the Hack-a-Sat CTF's flag format

  strings:
    $flag = /flag\{\w+:[a-zA-Z0-9\-\_]+\}/

  condition:
    any of them

}
