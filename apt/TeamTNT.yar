import "hash"

rule teamtnt_common_strings {

    meta:
      author = "Chad Baxter"
      author_email = "cbax@doslabelectronics.com"
      date = "2021-10-08"
      description = "Common strings in TeamTNT scripts and binaries"

    strings:
      $kill_string = "HaXXoRsMoPPeD" //set this as your hostname to stop all TeamTNT scripts early in their execution.
      $username = "hilde"
      $password = "/BnKiPmXA2eAQ" //crypt(3)
      $email = "hilde@teamtnt.red"
      $domain0 = "chimaera.cc"
      $domain1 = "teamtnt.red"
      $domain2 = "ipv4.icanhazip.com"
      $ip0 = "45.9.148.182"
      $compromized_ip0 = "85.214.149.236"

    condition:
      any of them

}