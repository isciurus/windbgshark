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
goto UNINSTALL


:x64
Set subfolder=%~dp0x64
goto UNINSTALL


:UNINSTALL

sc stop windbgshark_drv >nul
IF NOT %ERRORLEVEL% == 0 (
	IF NOT %ERRORLEVEL% == 1060 (
		IF NOT %ERRORLEVEL% == 1062 (
			echo Error removing service for driver module
			goto ERROR
		)
	)
)

sc delete windbgshark_drv >nul
IF NOT %ERRORLEVEL% == 0 (
	IF NOT %ERRORLEVEL% == 1060 (
		echo Error removing service for driver module
		goto ERROR
	)
)


REM Rollback previous AeDebug values

reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /f
reg copy "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug_wdbgshrk_backup" "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /s /f

reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /f
reg copy "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug_wdbgshrk_backup" "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /s /f

IF NOT %ERRORLEVEL% == 0 (
	echo Error uninstalling crash monitor
	goto ERROR
)

reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug_wdbgshrk_backup" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug_wdbgshrk_backup" /f

IF NOT %ERRORLEVEL% == 0 (
	echo Error uninstalling crash monitor
	goto ERROR
)

:SUCCESS
echo Windbgshark guest module uninstalled successfully.
goto FINISH

:ERROR
echo Windbgshark guest module not uninstalled
goto FINISH

:FINISH
pause