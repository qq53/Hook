@echo off
title Assembly Auto Build Script By Sen1993
color 0A
set var=C:\masm32\bin
set syst=windows
set desktop=%userprofile%\Desktop
pushd %var%
:@compile
@echo off
set f1=dll
%var%\ml.exe /c /coff /Fo %f1%.obj %desktop%\%f1%.asm
if not exist %f1%.obj @echo:±‡“Î¥ÌŒÛ!
if not exist %f1%.obj pause
if not exist %f1%.obj exit
%var%\link.exe /subsystem:%syst% %f1%.obj /Dll /out:%f1%.dll
if not exist %f1%.dll @echo:¡¥Ω”¥ÌŒÛ!
if not exist %f1%.dll pause
if not exist %f1%.dll exit
del %f1%.obj
move %f1%.dll %desktop%\exe\hook.dll