@echo off
title Assembly Auto Build Script By Sen1993
color 0A
set var=C:\masm32\bin
set inc=C:\masm32\include
set syst=console
set desktop=%userprofile%\Desktop\exe
pushd %var%
:@compile
@echo off
set f1=exe
%var%\ml.exe /c /coff /Fo %f1%.obj /I %inc% %desktop%\%f1%.asm
if not exist %f1%.obj @echo:±‡“Î¥ÌŒÛ!
if not exist %f1%.obj pause
if not exist %f1%.obj exit
%var%\link.exe /subsystem:%syst% %f1%.obj /out:%f1%.exe
if not exist %f1%.exe @echo:¡¥Ω”¥ÌŒÛ!
if not exist %f1%.exe pause
if not exist %f1%.exe exit
del %f1%.obj
move %f1%.exe %desktop%