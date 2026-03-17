import "macho"
import "hash"

rule macos_cleaner_loader : macho loader
{
    meta:
        author      = "initz3r0"
        description = "macOS Cleaner Mach-O loader with encrypted __const blob"
        hash        = "ee86fce7eed2adfd7a2eb468bd33a390b1bf5492a67c755cf7ed05e8ceb75110"

    strings:
        $s1 = "/usr/lib/libSystem.B.dylib" ascii
        $s2 = "/usr/lib/libc++.1.dylib" ascii
        $s3 = "_fork" ascii
        $s4 = "_pipe" ascii
        $s5 = "_dup2" ascii
        $s6 = "_execl" ascii
        $s7 = "_execvp" ascii
        $s8 = "XaytTPo89ojwdoxuaSrogGuX13Exo7qrcRoR6U8gPvrY3YAq" ascii

    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA) and
        all of them and
        filesize > 5MB
}


rule macos_cleaner_loader_bytepat : macho loader
{
    meta:
        author      = "initz3r0"
        description = "macOS Cleaner loader state machine constants"
        hash        = "ee86fce7eed2adfd7a2eb468bd33a390b1bf5492a67c755cf7ed05e8ceb75110"

    strings:
        $s1 = "XaytTPo89ojwdoxuaSrogGuX13Exo7qr" ascii
        $s2 = { F5 80 52 }
        $s3 = { A0 72 80 52 }
        $s4 = { A9 07 00 00 }
        $s5 = { BF 95 03 00 00 }

    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA) and
        $s1 and
        ($s2 or $s4) and
        ($s3 or $s5)
}


rule macos_cleaner_stealer_applescript
{
    meta:
        author      = "initz3r0"
        description = "macOS Cleaner obfuscated AppleScript stealer"

    strings:
        $s1 = "pvqchvusydge"
        $s2 = "akcssdpybutq"
        $s3 = "riapfzqnje"
        $s4 = "dqlvjacuikk"
        $s5 = "ibvwubjmcagh"
        $s6 = "dxtephqkngbz"
        $s7 = "rdovbwllmnmo"
        $s8 = "yynhqmzolvbl"

    condition:
        ($s1 and 2 of ($s2, $s3, $s4)) or
        (4 of ($s5, $s6, $s7, $s8))
}


rule macos_cleaner_stealer_generic
{
    meta:
        author      = "initz3r0"
        description = "AppleScript stealer with fake auth dialog and credential harvesting"

    strings:
        $s1 = "display dialog" ascii
        $s2 = "hidden answer" ascii
        $s3 = "dscl . authonly" ascii
        $s4 = "find-generic-password" ascii
        $s5 = "-ga \"Chrome\"" ascii
        $s6 = "login.keychain-db" ascii
        $s7 = "ditto -c -k" ascii
        $s8 = "X-Chunk-ID" ascii

    condition:
        ($s1 and $s2 and $s3) or
        ($s4 and $s5 and $s6 and $s7) or
        ($s8 and $s3) or
        (5 of them)
}


rule macos_cleaner_delivery
{
    meta:
        author      = "initz3r0"
        description = "macOS Cleaner delivery scripts from ptrei.com"

    strings:
        $s1 = "aHR0cHM6Ly9wdHJlaS5jb20v" ascii
        $s2 = "/tmp/helper" ascii
        $s3 = "xattr -c" ascii
        $s4 = "chmod +x" ascii
        $s5 = "cleaner3/update" ascii

    condition:
        $s1 or
        ($s2 and $s3 and $s4) or
        ($s5 and ($s2 or $s3))
}


rule macos_cleaner_persistence
{
    meta:
        author      = "initz3r0"
        description = "macOS Cleaner LaunchDaemon persistence plist"

    strings:
        $s1 = "com.finder.helper" ascii
        $s2 = ".mainhelper" ascii
        $s3 = "KeepAlive" ascii
        $s4 = "RunAtLoad" ascii

    condition:
        all of them and
        filesize < 4096
}


rule macos_cleaner_exfil
{
    meta:
        author      = "initz3r0"
        description = "macOS Cleaner exfil with campaign IDs or C2 domains"

    strings:
        $s1 = "laislivon.com" ascii
        $s2 = "wusetail.com" ascii
        $s3 = "ditto -c -k --sequesterRsrc" ascii
        $s4 = "split -b 25M" ascii
        $s5 = "BuildID" ascii
        $s6 = "X-Chunk-ID" ascii

    condition:
        (($s1 or $s2) and ($s3 or $s4)) or
        ($s5 and $s6 and ($s1 or $s2))
}
