@echo off
 
Set RegQry=HKLM\Hardware\Description\System\CentralProcessor\0
 
REG.exe Query %RegQry% > checkOS.txt
 
Find /i "x86" < CheckOS.txt >nul
 
If %ERRORLEVEL% == 0 (
    Goto x86
) ELSE (
    Goto x64
)


REM todo: backup old values

:x86
Set subfolder=%~dp0x86
goto INSTALL


:x64
Set subfolder=%~dp0x64
goto INSTALL


:INSTALL

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Debugger /t REG_SZ /d "\"%subfolder%\windbg.exe\" -p %%ld -e %%ld -g -QY -c \".load %subfolder%\wdbgshark_crashmon;!notifykdbg\"" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Auto /t REG_SZ /d "1" /f >nul
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Debugger /t REG_SZ /d "\"%subfolder%\windbg.exe\" -p %%ld -e %%ld -g -QY -c \".load %subfolder%\wdbgshark_crashmon;!notifykdbg\"" /f >nul
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Auto /t REG_SZ /d "1" /f >nul

echo Windbgshark guest module installed successfully.
pause