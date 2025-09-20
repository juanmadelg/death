rule MAL_Iceid_Trojan
{
    meta:
        author = "Juanma"
        description = "Detects IceID"
        date = "9/17/2025"
        reference = "https://tria.ge/231129-3w971seb6w/static1"
        hash = "cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    strings:
        $s1 = "/PASSWORD=password" wide
        $S2 = "Specifies the password to use." wide
 
    condition:
        pe.is_pe and
        filesize < 4500KB and
        all of them
}
