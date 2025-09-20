import "pe"

rule MAL_Latrodectus_Trojan
{
    meta:
        author = "Juanma"
        description = "Detects Latrodectus"
        date = "9/17/2025"
        reference = "https://cybersecsentinel.com/latrodectus-malware/"
        hash = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    strings:
        $s1 = "WATAUAVAWH" nocase
        $s2 = "MemFreeAndNullWithTagCheckFullMemory"
        $s3 = /[a-z]{1}:\\Build\\PETRU-DEFAULT-SOURCES\\inc\\ptportmisc.h/i //case insensitive
        $s4 = /[a-z]{1}:\\builds\\(\w|\d)*\\trufos_dll\\[a-z]+.c/ nocase
        $s5 = "\\Systemroot\\TrfDefData.tmp" wide
        $s6 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" wide

    condition:
        pe.is_pe and
        pe.imports("Secur32.dll") and // "Fltlib.dll"?
        all of them
}