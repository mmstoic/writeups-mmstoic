# FLARE-On 2025: Challenge 4 (in progress)

## Context

We are just provided with a file `UnholyDragon-150.exe`.

## Background Information

## Analysis

We begin as always by inspecting the given file. I ran `file` and was met with nothing particularly useful:

```
FLARE-VM 01/11/2026 20:29:57
PS C:\Users\flare\Desktop > file .\UnholyDragon-150.exe
.\UnholyDragon-150.exe: data
```

I also ran `strings` and noticed two groups of non-gibberish words. These strings can be found in `useful-strings.txt` which is in the same directory as this writeup. One group contained functions from popular Windows libraries, like FreeLibrary, GetProcAddress, and LoadLibraryW. The other group had some function names unfamiliar to me. I pasted these strings into an LLM to see if it could help decipher them, and it said this is indicative of a Windows GUI executable built with Virtual Basic 6. I kept this in mind as I continued inspecting the file.

PEiD said the file was not a valid PE executable and running the binary failed, so I opened it up in a hex editor. There were a couple of interesting things, particularly that the file's "MZ" magic bytes were `.Z' and the DDOS message present in Windows executables was "This program must be run under Windows." I went one by one correcting these quirks.

After changing ".Z" to "MZ", I ran file on the binary again, and recieved a different output:

```
FLARE-VM 01/11/2026 20:30:07
PS C:\Users\flare\Desktop > file .\UnholyDragon-150.exe
.\UnholyDragon-150.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

Additionally, I ran the fixed binary was got 4 more Unholy Dragon files in my current directory:

```
-a----         1/11/2026   8:55 PM        2721792 UnholyDragon-150.exe
-a----         1/11/2026   8:57 PM        2721792 UnholyDragon-151.exe
-a----         1/11/2026   8:57 PM        2721792 UnholyDragon-152.exe
-a----         1/11/2026   8:57 PM        2721792 UnholyDragon-153.exe
-a----         1/11/2026   8:57 PM        2721792 UnholyDragon-154.exe
```

I then experimented by removing latter Unholy Dragon files and found that only files up to #154 would generate. Additionally, in order to create a new Unholy Dragon file, there can't be one of that number already present in the given directory.

I believe that a thorough basic static analysis can save you a lot of time, so I opened the binary in CFF explorer to see what function it was using to get the name of an Unholy Dragon file (assuming it needs to get this name in order to make a new file of a slightly different name). The binary was found to use GetFullPathNameW, GetModuleFileNameW, and CopyFileW which would all be useful to look for. 

## Reversing

Opening up the binary in IDA, I first did a scan of the disassembly to map out the layout of the binary and name some subroutines, and then I jumped into looking for where GetFullPathNameW was called. 




## Remediation

# Sources/Credits

Written by Madalina Stoicov




