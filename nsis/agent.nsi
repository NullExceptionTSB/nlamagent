OutFile "..\setup.exe"
SetCompress force
SetCompressor /SOLID /FINAL lzma
XPStyle on

!include "MUI2.nsh"
!include "nsDialogs.nsh"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
Page Custom ServInfo ServInfoLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Var _
Var Uname
Var Passwd

Var UserName
var Password
Function ServInfo
	!insertmacro MUI_HEADER_TEXT "Service Settings" "Specify the service's login credentials"
	nsDialogs::Create 1018
	Pop $_

	${NSD_CreateLabel} 0 0 100% 12u "Username:"
	Pop $_

	${NSD_CreateText} 0 13u 100% 12u "NLAMAgent"
	Pop $Uname

	${NSD_CreateLabel} 0 30u 100% 12u "Password:"
	Pop $_

	${NSD_CreatePassword} 0 43u 100% 12u ""
	Pop $Passwd

	nsDialogs::Show
FunctionEnd

Function ServInfoLeave
	${NSD_GetText} $Uname $0
	StrCpy $UserName $0
	StrLen $0 $0

	${If} $0 <= 0
		MessageBox MB_ICONSTOP "A username must be specified"
		Abort
	${EndIf}

	${NSD_GetText} $Passwd $0
	StrCpy $Password $0
	StrLen $0 $0

	${If} $0 <= 0
		MessageBox MB_ICONSTOP "A password must be specified"
		Abort
	${EndIf}	
FunctionEnd

Name "NLAM Agent"

InstallDir "C:\Program Files\NLAM Agent"

!macro TestFunction UN
Function ${UN}RemoveAllFiles
   	Delete $INSTDIR\nlamagent.exe
	Delete $INSTDIR\uninstall.exe
	RMDir /r /REBOOTOK $INSTDIR
FunctionEnd
!macroend
!insertmacro TestFunction "" 
!insertmacro TestFunction "un."

Function Rollback
	DetailPrint "Error, rolling back changes.."
	Call RemoveAllFiles
FunctionEnd

Section
	SetOutPath $INSTDIR
	SetDetailsPrint lastused

	File ..\nlamagent.exe
	File ..\dll\*.dll

	WriteUninstaller $INSTDIR\uninstall.exe

	DetailPrint "Registering NLAMAgent service"

	SimpleSC::InstallService "NLAMAgent" "NLAM Agent" 16 2  $INSTDIR\nlamagent.exe "" $UserName $Password
	Pop $0

	${If} $0 != 0
		StrCpy $1 "Failed to register service, (lasterror code $0)"
		
		Call Rollback

		MessageBox MB_ICONSTOP $1
		Abort
	${EndIf}
SectionEnd

Section "uninstall"
	Call un.RemoveAllFiles
SectionEnd

