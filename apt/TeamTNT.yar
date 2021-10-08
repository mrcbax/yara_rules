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

rule teamtnt_hashes {

    meta:
      author = "Chad Baxter"
      author_email = "cbax@doslabelectronics.com"
      date = "2021-10-08"
      description = "Hashes of TeamTNT scripts and binaries"

    strings:
      $dummy = ""

    condition:
      hash.sha256(0, filesize) ==
        "0085bf33d4e4e051a15a1bd70636055d709aeef79025080afc7a8148ece55339" or
      hash.sha256(0, filesize) ==
        "024445ae9d41915af25a347e47122db2fbebb223e01acab3dd30de4b35464965" or
      hash.sha256(0, filesize) ==
        "06e8e4e480c4f19983f58c789503dbd31ee5076935a81ed0fe1f1af69b6f1d3d" or
      hash.sha256(0, filesize) ==
        "0ae5c1ddf91f8d5e64d58eb5395bf2216cc86d462255868e98cfb70a5a21813f" or
      hash.sha256(0, filesize) ==
        "19575166abd57feccf7cb0a1459daf476e736b7386c54a2b3320b2fc6ae12b9d" or
      hash.sha256(0, filesize) ==
        "232c127d6745e398f168faa30eea0648ef425df643f46b67401cda635ef81368" or
      hash.sha256(0, filesize) ==
        "44aa10cac2e84a6b08ddfca5ef8b16ce49cf48bdaffa3f59058f4e40e815fe8f" or
      hash.sha256(0, filesize) ==
        "480ecc5bb594fe3977180aa661858c8340f85e54cf302a6622f2a06b40349aa4" or
      hash.sha256(0, filesize) ==
        "48f92bdc4c039437ba77e6c6a74bb0d4b747aa94fb815223ea6d735d04fcb733" or
      hash.sha256(0, filesize) ==
        "4a00f99ce55f6204abcfa0b0392c6ee4c6a9fa46e8c1015a7c411ccd1b456720" or
      hash.sha256(0, filesize) ==
        "54701a4311150449e99386fe95b21c7a016dbf492f3b25022051d5043897a160" or
      hash.sha256(0, filesize) ==
        "5483941dcb2fb017850f3d358e4b1cc45837f30f517ebbbb0718947c5c4d5d50" or
      hash.sha256(0, filesize) ==
        "5dc3daf24fcef6ccaef2fec45bbb554f8090930d92a76f5d4c5a1f2487e484e0" or
      hash.sha256(0, filesize) ==
        "6075906fbc8898515fe09a046d81ca66429c9b3052a13d6b3ca6f8294c70d207" or
      hash.sha256(0, filesize) ==
        "6158197143f1696368e5a0b26f995b9801c2b29ca2e09d6f0aeb374a0fb3ce1b" or
      hash.sha256(0, filesize) ==
        "71af0d59f289cac9a3a80eacd011f5897e0c8a72141523c1c0a3e623eceed8a5" or
      hash.sha256(0, filesize) ==
        "7856273b2378b5a46e87fd8f91411c3c068a28c20d120d953e5307d5704ae0a2" or
      hash.sha256(0, filesize) ==
        "8425f835877c05c2ce49f75e93df25bcc80a7011feac2bcf6bc44862ea3eab88" or
      hash.sha256(0, filesize) ==
        "8768d25402bc1757fef4c601aa4b401992a959d8817762470b0f462f69afbefd" or
      hash.sha256(0, filesize) ==
        "8bb87c1bb60cbf88724e88cf75889e6aa4fba24ab92a14aa108be04841a7aa86" or
      hash.sha256(0, filesize) ==
        "9587323e9702889d095843921339abc9991af389f3417f591f329ab7338c19de" or
      hash.sha256(0, filesize) ==
        "962ee50e8b9537bd881cc3c3faed631e964319e22cf5a0fadfb91861d230af46" or
      hash.sha256(0, filesize) ==
        "96a52109973d50174252b05be64f3ddf0182137fc4186d7a5cef989a4604010d" or
      hash.sha256(0, filesize) ==
        "a21f3c05ac47f21dc0cc3db6f46e1a8fd1613d5656fb3e1bf8ab35c8f733a76d" or
      hash.sha256(0, filesize) ==
        "ad11da95afd2b62690afc37b40058d8b7adf63eef0caf61b4f251e75d25cfb3b" or
      hash.sha256(0, filesize) ==
        "b07ca49abd118bc2db92ccd436aec1f14bb8deb74c29b581842499642cc5c473" or
      hash.sha256(0, filesize) ==
        "be4974330db296bad8d33d9b150dc756b88edf864163b4c7ed89548058631ad4" or
      hash.sha256(0, filesize) ==
        "c50a95f2e5e17427168ef3b99a54704dc75bd41965e5ab68faac391f72560c2c" or
      hash.sha256(0, filesize) ==
        "c57f61e24814c9ae17c57efaf4149504e36bd3e6171e9299fd54b6fbb1ec108c" or
      hash.sha256(0, filesize) ==
        "ccc4b1e3045b49fe0af7128114b8befe5063058eaeb095c81a417d847b3e16ee" or
      hash.sha256(0, filesize) ==
        "cef2707760086718175235810e3e49a7bbfedce482dee09eef3d302247e97142" or
      hash.sha256(0, filesize) ==
        "dd60805ec68e3285a2cd4f32083f10a8571e81fb99c03434359bf339011a4a4c" or
      hash.sha256(0, filesize) ==
        "de651f9bc4e26a09a0d1ebc63a36c6139593bef6625822d59b2ccf37452ef716" or
      hash.sha256(0, filesize) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" or
      hash.sha256(0, filesize) ==
        "ea02410b2983cfa8cf6740f1f0dbd41d3d07da3f8d2b64ca85defa83060cae72" or
      hash.sha256(0, filesize) ==
        "f05155c8be6efbd94c0ec891494aa064a93def34b122bd70b4d225ea13fffff9" or
      hash.sha256(0, filesize) ==
        "fa2a7374219d10a4835c7a6f0906184daaffd7dec2df954cfa38c3d4dd62d30d"

}