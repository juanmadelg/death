import "pe"

rule MAL_Asyncrat_Trojan
{
    meta:
        author = "Juanma"
        description = "Detects Asyncrat"
        date = "9/16/2025"
        reference = "https://threatfox.abuse.ch/ioc/1252790/"
        hash = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    strings:
        $s1 = "ABRIL.exe" nocase
        $s2 = "/c schtasks /create /f /sc onlogon /rl highest /tn " wide
        $s3 = "Ergo_Wallet" nocase wide
        $s4 = "Bitcoin_Core" nocase wide
        $s5 = "Reset Scale succeeded!" nocase wide
        $s6 = "/c taskkill.exe /im chrome.exe /f" wide
        $s7 = "Stub.exe" nocase wide
        $s8 = "AVRemoval.Class1" nocase wide
        $s9 = "/c taskkill.exe /im chrome.exe /f" wide
        $s10 = "Select * from AntivirusProduct" wide

    condition:
        pe.is_pe and
        filesize < 6000KB and
        all of them
}
