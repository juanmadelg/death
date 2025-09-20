import "pe"

rule MAL_Darkgate_Trojan
{
    meta:
        author = "Juanma"
        description = "Detects Darkgate"
        date = "9/17/2025"
        reference = "https://bazaar.abuse.ch/sample/0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23/"
        hash = "0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23"
    strings:
        $s1 = "[AntiDebug] [user_check()] Username:" nocase
        $s2 = "LOUISE-PC" nocase
        $s3 = "\\System32\\vmGuestLib.dll"
        $s4 = "rundll32 cleanhelper.dll T34 /k funtic321 1"
        $s5 = "cdn3-adb1.online" wide
        $s6 = "-SilentCleanup.xml.txt" wide
     condition:
        pe.is_pe and
        filesize < 2000KB and
        pe.imports("WINHTTP.dll") and
        all of them
}
