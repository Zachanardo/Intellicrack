@echo off
REM Java linter using Checkstyle
REM Usage: lint-java [file/directory]

if "%1"=="" (
    echo Usage: lint-java [file or directory]
    echo Examples:
    echo   lint-java MyClass.java
    echo   lint-java src/
    echo   lint-java com/example/*.java
    exit /b 1
)

REM Use Google's Java style guide (most popular)
java -jar checkstyle.jar -c /google_checks.xml %1
