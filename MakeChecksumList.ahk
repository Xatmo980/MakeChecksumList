Loop Files, *.esp
     V .= "    {""" . N := A_LoopFileName . """: [""0x" . crc := FileCRC32(sFile := A_LoopFileName) . """]}" . "`,"
R := SubStr(V, 1, (Str := StrLen(V) -1))
If R =
 {
  MsgBox % "There are no esp files here"
  ExitApp
 }

Loop, parse, R
{
 C := A_LoopField
 If C = ,
   {
    X .= A_LoopField . "`n"
   }
 else
   {
    X .= A_LoopField
   }
}

FileAppend,
(
[
    {"Morrowind.esm": ["0x7B6AF5B9", "0x34282D67"]},
    {"Tribunal.esm": ["0xF481F334", "0x211329EF"]},
    {"Bloodmoon.esm": ["0x43DD2132", "0x9EB62F26"]},
%X%
]
), requiredDataFiles.json

FileCRC32(sFile := "", cSz := 4) ; Author ........: jNizM
{
    Bytes := ""
    cSz := (cSz < 0 || cSz > 8) ? 2**22 : 2**(18 + cSz)
    VarSetCapacity(Buffer, cSz, 0)
    hFil := DllCall("Kernel32.dll\CreateFile", "Str", sFile, "UInt", 0x80000000, "UInt", 3, "Int", 0, "UInt", 3, "UInt", 0, "Int", 0, "UInt")
    if (hFil < 1)
    {
        return hFil
    }
    hMod := DllCall("Kernel32.dll\LoadLibrary", "Str", "Ntdll.dll")
    CRC := 0
    DllCall("Kernel32.dll\GetFileSizeEx", "UInt", hFil, "Int64", &Buffer), fSz := NumGet(Buffer, 0, "Int64")
    loop % (fSz // cSz + !!Mod(fSz, cSz))
    {
        DllCall("Kernel32.dll\ReadFile", "UInt", hFil, "Ptr", &Buffer, "UInt", cSz, "UInt*", Bytes, "UInt", 0)
        CRC := DllCall("Ntdll.dll\RtlComputeCrc32", "UInt", CRC, "UInt", &Buffer, "UInt", Bytes, "UInt")
    }
    DllCall("Kernel32.dll\CloseHandle", "Ptr", hFil)
    SetFormat, Integer, % SubStr((A_FI := A_FormatInteger) "H", 0)
    CRC := SubStr(CRC + 0x1000000000, -7)
    DllCall("User32.dll\CharLower", "Str", CRC)
    SetFormat, Integer, %A_FI%
    return CRC, DllCall("Kernel32.dll\FreeLibrary", "Ptr", hMod)
}