@echo off
setlocal
for %%e in (
	.bat .cmd .chm .hta .jse .js .vbe .vbs
	.wsc .wsf .ws .wsh .sct .url .ps1 .reg
	.wcx .slk .iqy .prn .diff .rdg .application .deploy
) do (
	assoc %%e=txtfile >nul 2>&1
)
endlocal
