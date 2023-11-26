OutFile "..\setup.exe"
SetCompress force
SetCompressor /SOLID /FINAL lzma
XPStyle on

!include "MUI2.nsh"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Name "NLAM Agent"

InstallDir "C:\Program Files\NLAM Agent"

Section
    SimpleSC::InstallService "NLAMAgent" "NLAM Agent" 16 2 $INSTDIR\nlamagent "" 
	SetOutPath $INSTDIR
	
	WriteUninstaller $INSTDIR\uninstall.exe

	File ..\nlamagent.exe
SectionEnd

Section "uninstall"
	Delete $INSTDIR\nlamagent.exe

	RMDir $INSTDIR
SectionEnd