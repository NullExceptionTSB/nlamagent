OutFile "asetup.exe"
SetCompress force
SetCompressor /SOLID /FINAL lzma
XPStyle on

!include "MUI2.nsh"
!include "nsDialogs.nsh"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
Page Custom ServInfo ServInfoLeave
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Var _
Var Input

Function ServInfo
	!insertmacro MUI_HEADER_TEXT "Do it" "Say gex"
	nsDialogs::Create 1018
	Pop $_

	${NSD_CreateLabel} 0 0 100% 12u "Say gex"
	Pop $_

	${NSD_CreateText} 0 13u 100% 12u "Say gex"
	Pop $Input

	nsDialogs::Show
FunctionEnd

Function ServInfoLeave
	${NSD_GetText} $Input $0

	${If} $0 != "gex"
		MessageBox MB_ICONSTOP "Nu uh!"
		Abort
	${EndIf}
	MessageBox MB_OK "Yipee!"
	
FunctionEnd

Name "NLAM Agent"

InstallDir "C:\Program Files\NLAM Agent"

Section
	SetOutPath $INSTDIR
SectionEnd

Section "uninstall"
	Delete $INSTDIR\nlamagent.exe

	RMDir $INSTDIR
SectionEnd