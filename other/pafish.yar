import "pe"

rule pafish {
  strings:
    $1 = "Sandbox traced by checking common sample names in drives root"
  condition:
    pe.version_info["FileDescription"] == "Paranoid Fish is paranoid" and pe.version_info["ProductName"] == "Paranoid Fish" and $1
}
