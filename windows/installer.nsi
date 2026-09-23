; SPDX-License-Identifier: AGPL-3.0-or-later
;
; The zond installer: a per-user install that needs no administrator.
; Built by windows/build.sh, which passes VERSION and DIST.
;
; Puts zond.exe in %LOCALAPPDATA%\Programs\zond and adds that folder and
; Npcap's to the user's PATH. zond.exe imports wpcap.dll, which Npcap keeps in
; System32\Npcap unless it was installed in WinPcap-compatible mode.

Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "StrFunc.nsh"
!include "WinMessages.nsh"
!include "x64.nsh"

${StrStr}
${UnStrRep}

!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\zond"
!define NPCAP_DIR "%SystemRoot%\System32\Npcap"

Name "zond ${VERSION}"
OutFile "${DIST}\zond-${VERSION}-setup.exe"
InstallDir "$LOCALAPPDATA\Programs\zond"
RequestExecutionLevel user
SetCompressor /SOLID lzma

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.txt"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${DIST}\LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Appends `entry` to the user's PATH unless it is already there, leaving $2 at
; 1 when it added it and 0 when it was there already.
!macro AddToUserPath entry
  StrCpy $2 0
  ReadRegStr $0 HKCU "Environment" "Path"
  ${StrStr} $1 ";$0;" ";${entry};"
  ${If} $1 == ""
    StrCpy $2 1
    ${If} $0 == ""
      WriteRegExpandStr HKCU "Environment" "Path" "${entry}"
    ${Else}
      WriteRegExpandStr HKCU "Environment" "Path" "$0;${entry}"
    ${EndIf}
  ${EndIf}
!macroend

; Removes `entry` from the user's PATH, wherever it stands.
!macro RemoveFromUserPath entry
  ReadRegStr $0 HKCU "Environment" "Path"
  StrCpy $0 ";$0;"
  ${UnStrRep} $0 $0 ";${entry};" ";"
  StrCpy $0 $0 "" 1
  StrLen $1 $0
  ${If} $1 > 0
    IntOp $1 $1 - 1
    StrCpy $0 $0 $1
  ${EndIf}
  WriteRegExpandStr HKCU "Environment" "Path" "$0"
!macroend

Function .onInit
  ; Npcap registers itself in the 64-bit hive.
  SetRegView 64
  ReadRegStr $0 HKLM "SOFTWARE\Npcap" ""
  SetRegView 32
  ${DisableX64FSRedirection}
  ${If} $0 == ""
  ${AndIfNot} ${FileExists} "$WINDIR\System32\Npcap\wpcap.dll"
  ${AndIfNot} ${FileExists} "$WINDIR\System32\wpcap.dll"
    ${EnableX64FSRedirection}
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "Npcap does not appear to be installed.$\r$\n$\r$\nzond needs Npcap's wpcap.dll to start. Install it from https://npcap.com before running zond.$\r$\n$\r$\nOpen npcap.com now? (Setup continues either way.)" IDNO +2
      ExecShell "open" "https://npcap.com/#download"
  ${Else}
    ${EnableX64FSRedirection}
  ${EndIf}
FunctionEnd

Section "zond"
  SetOutPath "$INSTDIR"
  File "${DIST}\zond.exe"
  File "${DIST}\README.txt"
  File "${DIST}\LICENSE.txt"

  !insertmacro AddToUserPath "$INSTDIR"
  !insertmacro AddToUserPath "${NPCAP_DIR}"
  ; Remembered, so the uninstaller takes Npcap's folder off PATH only if this
  ; installer put it there.
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "AddedNpcapToPath" $2
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "zond ${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "zond"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\zond.exe"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  !insertmacro RemoveFromUserPath "$INSTDIR"
  ReadRegDWORD $3 HKCU "${UNINSTALL_KEY}" "AddedNpcapToPath"
  ${If} $3 == 1
    !insertmacro RemoveFromUserPath "${NPCAP_DIR}"
  ${EndIf}
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000

  DeleteRegKey HKCU "${UNINSTALL_KEY}"
SectionEnd
