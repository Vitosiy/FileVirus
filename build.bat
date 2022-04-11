jwasm -bin -nologo -Fo bin/v64.bin /I "C:\wininc\Include" -10p -zf0 -W2 -D_WIN64 src/virus.asm
jwasm -bin -nologo -Fo bin/v32.bin /I "C:\masm32\include" -W2 src/virus.asm