import "pe"

rule MAL_Pikabot_Trojan
{
    meta:
        author = "Juanma"
        description = "Detects Pikabot"
        date = "9/17/2025"
        reference = "https://bazaar.abuse.ch/sample/7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e/"
        hash = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    strings:
        $s1 = "PM.Promo.Toolbox.Datashredder" ascii
        $s2 = "!cILryP$LsPSiLpN" ascii
        $s3 = "SOFTWARE\\360TotalSecurity\\Experience" wide
        $s4 = "360TSCommon.dll" wide
        $s5 = "PromoUtil.exe" wide
        $s6 = "QHFileSmasher.exe" wide
        $s7 = "File Smasher Application" wide

    condition:
        pe.is_pe and
        filesize < 1500KB and
        all of them
}