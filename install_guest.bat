@echo off
 
Set RegQry=HKLM\Hardware\Description\System\CentralProcessor\0
 
REG.exe Query %RegQry% > checkOS.txt
 
Find /i "x86" < CheckOS.txt >nul
 
If %ERRORLEVEL% == 0 (
    Goto x86
) ELSE (
    Goto x64
)


:x86
Set subfolder=%~dp0x86
goto INSTALL


:x64
Set subfolder=%~dp0x64
goto INSTALL


:INSTALL

copy %subfolder%\windbgshark_drv.sys %WINDIR%\system32\drivers /Y >nul

IF NOT %ERRORLEVEL% == 0 (
	echo Error copying driver module to %WINDIR%\system32\drivers
	goto ERROR
)

sc create windbgshark_drv binpath= "system32\drivers\windbgshark_drv.sys" displayname= "windbgshark_drv" start= auto type= kernel >nul
IF %ERRORLEVEL% == 1073 (
	sc delete windbgshark_drv >nul
	sc create windbgshark_drv binpath= "system32\drivers\windbgshark_drv.sys" displayname= "windbgshark_drv" start= auto type= kernel >nul
)
IF NOT %ERRORLEVEL% == 0 (
	echo Error creating service for driver module
	goto ERROR
)

REM AeDebug backup so that uninstall will be possible
reg copy "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug_wdbgshrk_backup" /s /f >nul
reg copy "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug_wdbgshrk_backup" /s /f >nul

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Debugger /t REG_SZ /d "\"%subfolder%\windbg.exe\" -p %%ld -e %%ld -g -QY -c \".load %subfolder%\wdbgshark_crashmon;!notifykdbg\"" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Auto /t REG_SZ /d "1" /f >nul
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Debugger /t REG_SZ /d "\"%subfolder%\windbg.exe\" -p %%ld -e %%ld -g -QY -c \".load %subfolder%\wdbgshark_crashmon;!notifykdbg\"" /f >nul
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Auto /t REG_SZ /d "1" /f >nul

IF NOT %ERRORLEVEL% == 0 (
	echo Error installing crash monitor
	goto ERROR
)

echo Windbgshark guest module installed successfully.
pause
exit

:ERROR
echo Windbgshark guest module not installed
pause
exit