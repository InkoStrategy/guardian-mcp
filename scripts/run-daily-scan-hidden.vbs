' Launcher for the daily OKX.AI trust scan.
' wscript.exe is a GUI-subsystem host, so Task Scheduler never allocates a console window for it --
' unlike node.exe or powershell.exe, which flash a console and steal focus from fullscreen video and games.
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = "C:\Users\mynam\guardian-mcp"
sh.Run """C:\Program Files\nodejs\node.exe"" scripts\daily-scan.cjs --push", 0, True
