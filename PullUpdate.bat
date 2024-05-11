
setlocal enabledelayedexpansion
set "original_path=%CD%"
REM Replace \ with /
set "converted_path=!original_path:\=/!"



git config --global --add safe.directory %converted_path%

git add .
git commit -m "Local Save"
git status
git pull

endlocal
pause