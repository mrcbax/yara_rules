rule flag_regex {

strings:
$flag = /flag\{\w+:[a-zA-Z0-9\-\_]+\}/

condition:
any of them
}
