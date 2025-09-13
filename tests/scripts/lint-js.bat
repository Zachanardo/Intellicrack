@echo off
REM JavaScript/TypeScript linter using ESLint
REM Usage: lint-js [file/directory]

if "%1"=="" (
    echo Usage: lint-js [file or directory]
    echo Examples:
    echo   lint-js script.js
    echo   lint-js src/
    echo   lint-js "**/*.js"
    exit /b 1
)

REM Create basic ESLint config if it doesn't exist
if not exist .eslintrc.js (
    echo Creating basic ESLint config...
    echo module.exports = { > .eslintrc.js
    echo   "env": { >> .eslintrc.js
    echo     "browser": true, >> .eslintrc.js
    echo     "node": true, >> .eslintrc.js
    echo     "es2021": true >> .eslintrc.js
    echo   }, >> .eslintrc.js
    echo   "extends": ["eslint:recommended"], >> .eslintrc.js
    echo   "rules": { >> .eslintrc.js
    echo     "no-console": "warn", >> .eslintrc.js
    echo     "no-unused-vars": "error", >> .eslintrc.js
    echo     "semi": ["error", "always"], >> .eslintrc.js
    echo     "quotes": ["error", "single"] >> .eslintrc.js
    echo   } >> .eslintrc.js
    echo }; >> .eslintrc.js
)

REM Run ESLint
eslint %1
