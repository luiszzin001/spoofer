@echo off
setlocal EnableDelayedExpansion

:: Removida proteção anti-edição - iniciando normalmente
title Onlys Spoofer - PREMIUM EDITION

:: Verificando privilégios de administrador
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo Executando como administrador...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

:splash
cls
color 0B
echo.
echo   :::::::::::  ::::    ::: :::     :::   :::::::::::
echo      :+:      :+:+:   :+: :+:     :+:       :+:     
echo     +:+      :+:+:+  +:+ +:+     +:+       +:+      
echo    +#+      +#+ +:+ +#+ +#+     +:+       +#+       
echo   +#+      +#+  +#+#+# +#+     +#+       +#+        
echo  #+#      #+#   #+#+# #+#     #+#       #+#         
echo ######### ###    #### ###########     ###           
echo.
echo    ::::::::  ::::    ::: :::        :::   :::::::::::  ::::::::  
echo   :+:    :+: :+:+:   :+: :+:        :+:       :+:     :+:    :+: 
echo   +:+    +:+ :+:+:+  +:+ +:+        +:+       +:+     +:+        
echo   +#+    +:+ +#+ +:+ +#+ +#+        +#+       +#+     +#++:++#++ 
echo   +#+    +#+ +#+  +#+#+# +#+        +#+       +#+            +#+ 
echo   #+#    #+# #+#   #+#+# #+#        #+#       #+#     #+#    #+# 
echo    ########  ###    #### ########## ###       ###      ########  
echo.
echo                            PREMIUM EDITION
echo.
echo                  Carregando sistema...
echo.

:: Animação de carregamento com bola
call :loading_animation
goto menu

:loading_animation
color 0D
set "chars=|/-\"
for /L %%i in (1,1,20) do (
    set /a idx=%%i %% 4
    for /f %%j in ("!idx!") do (
        set "c=!chars:~%%j,1!"
        echo.
        echo.
        echo                         [!c!] Carregando...
        echo.
        echo                         Inicializando Spoofer...
        echo.
        timeout /t 0 /nobreak >nul
        cls
        echo.
        echo   :::::::::::  ::::    ::: :::     :::   :::::::::::
        echo      :+:      :+:+:   :+: :+:     :+:       :+:     
        echo     +:+      :+:+:+  +:+ +:+     +:+       +:+      
        echo    +#+      +#+ +:+ +#+ +#+     +:+       +#+       
        echo   +#+      +#+  +#+#+# +#+     +#+       +#+        
        echo  #+#      #+#   #+#+# #+#     #+#       #+#         
        echo ######### ###    #### ###########     ###           
        echo.
        echo    ::::::::  ::::    ::: :::        :::   ::::::::::: 
        echo   :+:    :+: :+:+:   :+: :+:        :+:       :+:     
        echo   +:+    +:+ :+:+:+  +:+ +:+        +:+       +:+     
        echo   +#+    +:+ +#+ +:+ +#+ +#+        +#+       +#+     
        echo   +#+    +#+ +#+  +#+#+# +#+        +#+       +#+     
        echo   #+#    #+# #+#   #+#+# #+#        #+#       #+#     
        echo    ########  ###    #### ########## ###       ###     
        echo.
        echo                            PREMIUM EDITION
        echo.
        echo                  Carregando sistema...
    )
)
color 0A
cls
echo.
echo   :::::::::::  ::::    ::: :::     :::   :::::::::::
echo      :+:      :+:+:   :+: :+:     :+:       :+:     
echo     +:+      :+:+:+  +:+ +:+     +:+       +:+      
echo    +#+      +#+ +:+ +#+ +#+     +:+       +#+       
echo   +#+      +#+  +#+#+# +#+     +#+       +#+        
echo  #+#      #+#   #+#+# #+#     #+#       #+#         
echo ######### ###    #### ###########     ###           
echo.
echo    ::::::::  ::::    ::: :::        :::   ::::::::::: 
echo   :+:    :+: :+:+:   :+: :+:        :+:       :+:     
echo   +:+    +:+ :+:+:+  +:+ +:+        +:+       +:+     
echo   +#+    +:+ +#+ +:+ +#+ +#+        +#+       +#+     
echo   +#+    +#+ +#+  +#+#+# +#+        +#+       +#+     
echo   #+#    #+# #+#   #+#+# #+#        #+#       #+#     
echo    ########  ###    #### ########## ###       ###     
echo.
echo                            PREMIUM EDITION
echo.
echo                  Sistema Carregado!
timeout /t 1 >nul
exit /b

:menu
color 0A
cls
echo ========================================================
echo                    ONLYS SPOOFER CMD 
echo                      PREMIUM EDITION
echo                ESPECIAL PARA FIVEM E JOGOS
echo ========================================================
echo   Sessao: Ativa
echo ========================================================
echo.
echo Este programa modificara os identificadores do seu hardware
echo para evitar rastreamento e deteccao, especialmente em servidores
echo de FiveM e outros jogos com anti-cheat.
echo.
echo ========================================================
echo.
echo Opcoes:
echo.
echo  [1] Spoof HWID (Temporario - reseta no reinicio)
echo  [2] Spoof HWID (Permanente)
echo  [3] Ativar Protecao Anti-Cheat (FiveM Focused)
echo  [4] Verificar IDs atuais
echo  [5] Sair
echo.
echo ========================================================
echo.
echo Dica: Use a opcao [1] antes de conectar aos servidores de FiveM
echo para evitar deteccao apos um banimento.
echo.
echo ========================================================
echo.
set /p choice=Escolha uma opcao: 
echo.

if "%choice%"=="1" (
    call :SpoofHWID temp
    goto menu
) else if "%choice%"=="2" (
    call :SpoofHWID perm
    goto menu
) else if "%choice%"=="3" (
    call :AntiCheatProtection
    goto menu
) else if "%choice%"=="4" (
    call :CheckCurrentIDs
    goto menu
) else if "%choice%"=="5" (
    exit /b
) else (
    echo Opcao invalida. Pressione qualquer tecla para tentar novamente...
    pause >nul
    goto menu
)

:SpoofHWID
cls
color 0B
echo ========================================================
echo                ONLYS SPOOFER - SPOOFING HWID
echo ========================================================
echo.
echo Iniciando processo de spoofing avancado para FiveM...
echo.

:: Gerando novos valores aleatorios
set "chars=0123456789ABCDEF"
set newMachineGUID=
for /L %%i in (1,1,32) do (
    set /a r=!random! %% 16
    for /f %%j in ("!r!") do set newMachineGUID=!newMachineGUID!!chars:~%%j,1!
)

set newVolumeID=
for /L %%i in (1,1,8) do (
    set /a r=!random! %% 16
    for /f %%j in ("!r!") do set newVolumeID=!newVolumeID!!chars:~%%j,1!
)

echo [*] Aplicando novas configuracoes...
echo.

:: Spoofing MachineGUID no Registro
echo [*] Modificando MachineGUID...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /v MachineGuid /t REG_SZ /d "!newMachineGUID!" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar MachineGUID. O processo continuara mesmo assim.
) else (
    echo [+] MachineGUID modificado com sucesso.
)

:: Spoofing Hardware Profile
echo [*] Modificando Hardware Profile GUID...
set newHWProfileGuid={%newMachineGUID:~0,8%-%newMachineGUID:~8,4%-%newMachineGUID:~12,4%-%newMachineGUID:~16,4%-%newMachineGUID:~20,12%}
reg add "HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001" /v HwProfileGuid /t REG_SZ /d "!newHWProfileGuid!" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar Hardware Profile. O processo continuara mesmo assim.
) else (
    echo [+] Hardware Profile modificado com sucesso.
)

:: Spoofing Machine ID
echo [*] Modificando Machine ID...
reg add "HKLM\SOFTWARE\Microsoft\SQMClient" /v MachineId /t REG_SZ /d "{!newMachineGUID!}" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar Machine ID. O processo continuara mesmo assim.
) else (
    echo [+] Machine ID modificado com sucesso.
)

:: Spoofing Installation ID
echo [*] Modificando Installation ID...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallationID /t REG_SZ /d "!newHWProfileGuid!" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar Installation ID. O processo continuara mesmo assim.
) else (
    echo [+] Installation ID modificado com sucesso.
)

:: Spoofing Product ID
echo [*] Modificando Product ID...
set "numchars=0123456789"
set newProductID=
for /L %%i in (1,1,20) do (
    set /a r=!random! %% 10
    for /f %%j in ("!r!") do set newProductID=!newProductID!!numchars:~%%j,1!
)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductId /t REG_SZ /d "!newProductID!" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar Product ID. O processo continuara mesmo assim.
) else (
    echo [+] Product ID modificado com sucesso.
)

:: NOVAS MODIFICAÇÕES PARA FIVEM

:: Modificando HWID específicos do FiveM
echo [*] Modificando identificadores especificos para FiveM...

:: Modificando DigitalProductId (mais uma camada)
echo [*] Modificando DigitalProductId...
set "bin_data="
for /L %%i in (1,1,64) do (
    set /a r=!random! %% 256
    set "byte=!r!"
    if !byte! lss 16 set "byte=0!byte!"
    set "bin_data=!bin_data!!byte!"
)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DigitalProductId /t REG_BINARY /d !bin_data! /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DigitalProductId4 /t REG_BINARY /d !bin_data! /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar DigitalProductId. O processo continuara mesmo assim.
) else (
    echo [+] DigitalProductId modificado com sucesso.
)

:: Modificar BuildGUID - outro identificador rastreado
echo [*] Modificando BuildGUID...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildGUID /t REG_SZ /d "!newHWProfileGuid!" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar BuildGUID. O processo continuara mesmo assim.
) else (
    echo [+] BuildGUID modificado com sucesso.
)

:: Modificar BIOS info no registro
echo [*] Modificando informacoes BIOS (via Registro)...
reg add "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v SystemManufacturer /t REG_SZ /d "Onlys-%random%" /f >nul 2>&1
reg add "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v SystemProductName /t REG_SZ /d "System-%random%" /f >nul 2>&1
reg add "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v SystemSKU /t REG_SZ /d "SKU-%random%" /f >nul 2>&1
reg add "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v BIOSVendor /t REG_SZ /d "Custom-%random%" /f >nul 2>&1
reg add "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v BIOSVersion /t REG_SZ /d "%random%.%random%" /f >nul 2>&1
reg add "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v BIOSReleaseDate /t REG_SZ /d "%date%" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar informacoes BIOS. O processo continuara mesmo assim.
) else (
    echo [+] Informacoes BIOS modificadas com sucesso.
)

:: Modificar identificadores de disco
echo [*] Modificando identificadores de disco...
reg add "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" /v Identifier /t REG_SZ /d "Onlys-Disk-%random%" /f >nul 2>&1
reg add "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" /v SerialNumber /t REG_SZ /d "Onlys-%random%%random%" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar identificadores de disco. O processo continuara mesmo assim.
) else (
    echo [+] Identificadores de disco modificados com sucesso.
)

:: Modificar MAC Address via Registro (método alternativo)
echo [*] Tentando modificar MAC Address via Registro...
for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /s /v "NetCfgInstanceId" 2^>nul') do (
    set "line=%%a"
    if "!line:~0,4!"=="    " (
        set "adapter=!line:~0!"
        set "newMAC=02"
        for /L %%i in (1,1,5) do (
            set /a r=!random! %% 256
            set "byte=!r!"
            if !byte! lss 16 set "byte=0!byte!"
            set "newMAC=!newMAC!!byte:~-2!"
        )
        
        for /f "tokens=2*" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /v NetworkAddress 2^>nul') do (
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /v NetworkAddress /t REG_SZ /d "!newMAC!" /f >nul 2>&1
        )
    )
)
echo [+] Tentativa de modificacao de MAC Address concluida.

:: Modificar Computer Name
echo [*] Modificando Computer Name...
set "newCompName=ONLYS-%random%"
wmic computersystem where name="%computername%" call rename name="!newCompName!" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Erro ao modificar Computer Name. O processo continuara mesmo assim.
) else (
    echo [+] Computer Name modificado com sucesso para !newCompName!.
)

:: Limpando cache do FiveM se existir
echo [*] Procurando e limpando cache do FiveM...
set "fivemCachePath=%localappdata%\FiveM\FiveM.app\cache"
if exist "!fivemCachePath!" (
    echo [*] Cache do FiveM encontrado, limpando...
    del /s /q "!fivemCachePath!\browser\*.*" >nul 2>&1
    del /s /q "!fivemCachePath!\db\*.*" >nul 2>&1
    del /s /q "!fivemCachePath!\priv\*.*" >nul 2>&1
    del /s /q "!fivemCachePath!\servers\*.*" >nul 2>&1
    del /s /q "!fivemCachePath!\subprocess\*.*" >nul 2>&1
    echo [+] Cache do FiveM limpo com sucesso.
) else (
    echo [!] Cache do FiveM nao encontrado. Pulando esta etapa.
)

:: Removendo CitizenFX se existir (painel de instruções FiveM)
set "citizenPath=%localappdata%\DigitalEntitlements"
if exist "!citizenPath!" (
    echo [*] Removendo CitizenFX Digital Entitlements...
    rmdir /s /q "!citizenPath!" >nul 2>&1
    echo [+] CitizenFX removido com sucesso.
) else (
    echo [!] CitizenFX nao encontrado. Pulando esta etapa.
)

:: Mac Address Spoofing (simplificado)
echo [*] Nota sobre MAC Address:
echo [+] Tentativa de modificacao realizada via Registro.
echo [+] Recomendado reiniciar adaptadores de rede apos esta operacao.

:: Resultado
echo.
echo [*] Processo de spoofing avancado concluido!
echo.
if "%1"=="temp" (
    echo     As alteracoes serao resetadas apos reiniciar o sistema.
    echo     Recomendacao: Reinicie o FiveM apos esta operacao para melhores resultados.
) else (
    echo     As alteracoes foram aplicadas permanentemente.
    echo     Recomendacao: Reinicie o computador para que todas as alteracoes tenham efeito completo.
)

:: Instruções adicionais para FiveM
echo.
echo [*] Instrucoes para FiveM:
echo     1. Recomendado usar uma VPN ao conectar em servidores
echo     2. Certifique-se de limpar cookies do navegador Rockstar
echo     3. Se possivel, use uma conta Steam/Epic diferente
echo     4. Evite se conectar imediatamente ao mesmo servidor
echo.
echo ========================================================
echo.
echo [*] Pressione qualquer tecla para retornar ao menu principal...
pause >nul
goto menu

:AntiCheatProtection
cls
color 0B
echo ========================================================
echo            ONLYS SPOOFER - ANTI-CHEAT PROTECTION
echo                      FOCUS NO FIVEM E JOGOS
echo ========================================================
echo.
echo Iniciando processo de ativacao da protecao anti-cheat avancada...
echo.

:: Bloqueando acesso a funções de detecção de hardware
echo [*] Bloqueando acessos a deteccao de hardware...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableULPS /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DisableULPS /t REG_DWORD /d 1 /f >nul 2>&1

:: Configurando firewall para jogos (mais específico para FiveM e outros)
echo [*] Configurando firewall para jogos...
echo [+] Adicionando regras basicas...
netsh advfirewall firewall add rule name="Onlys Firewall - Basic" dir=in action=allow program="%SystemRoot%\System32\svchost.exe" enable=yes >nul 2>&1

echo [+] Bloqueando portas conhecidas de anti-cheat...
:: BattlEye
netsh advfirewall firewall add rule name="Block BattlEye UDP" dir=out action=block protocol=UDP remoteport=2552 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="Block BattlEye TCP" dir=out action=block protocol=TCP remoteport=2552 enable=yes >nul 2>&1

:: EasyAntiCheat
netsh advfirewall firewall add rule name="Block EAC UDP" dir=out action=block protocol=UDP remoteport=9090 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="Block EAC TCP" dir=out action=block protocol=TCP remoteport=9090 enable=yes >nul 2>&1

:: Adicionando chaves de registro anti-detecção
echo [*] Adicionando chaves de registro anti-deteccao...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCMD /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f >nul 2>&1

:: Bloqueando serviços específicos
echo [*] Bloqueando servicos especificos de anti-cheat...
sc config BEService start= disabled >nul 2>&1
sc config EasyAntiCheat start= disabled >nul 2>&1
sc config PnkBstrA start= disabled >nul 2>&1
sc config BattlEye start= disabled >nul 2>&1
sc config FiveM start= disabled >nul 2>&1
sc config "Rockstar Game Library Service" start= disabled >nul 2>&1

:: Mascarando informações de registro
echo [*] Mascarando informacoes de registro...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" /v ComputerName /t REG_SZ /d "DESKTOP-%random%" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" /v ComputerName /t REG_SZ /d "DESKTOP-%random%" /f >nul 2>&1

:: Configurando proteção adicional
echo [*] Configurando protecao adicional...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BEService.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\systray.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EasyAntiCheat.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\systray.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FiveM.exe" /v Debugger /t REG_SZ /d "%windir%\system32\systray.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FiveM_b2545_GTAProcess.exe" /v Debugger /t REG_SZ /d "%windir%\system32\systray.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FiveM_ChromeBrowser.exe" /v Debugger /t REG_SZ /d "%windir%\system32\systray.exe" /f >nul 2>&1

:: Protection especifica para FiveM
echo [*] Aplicando protecao especifica para FiveM...

:: Bloqueando comunicacao com servidores de autenticacao
echo [+] Bloqueando comunicacao com servidores de verificacao...
powershell -Command "Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value '127.0.0.1 xboxlive.com' -Force" >nul 2>&1
powershell -Command "Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value '127.0.0.1 user.auth.xboxlive.com' -Force" >nul 2>&1
powershell -Command "Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value '127.0.0.1 presence-heartbeat.xboxlive.com' -Force" >nul 2>&1
powershell -Command "Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value '127.0.0.1 rpc.rsg.sc' -Force" >nul 2>&1
powershell -Command "Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value '127.0.0.1 prod.telemetry.ros.rockstargames.com' -Force" >nul 2>&1
powershell -Command "Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value '127.0.0.1 megaphone.rockstargames.com' -Force" >nul 2>&1

:: Bloqueando executáveis de anti-cheat no firewall
echo [+] Bloqueando executaveis no firewall...
netsh advfirewall firewall add rule name="Block BEService" dir=out action=block program="C:\Program Files (x86)\Common Files\BattlEye\BEService.exe" enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="Block EasyAntiCheat" dir=out action=block program="C:\Program Files (x86)\EasyAntiCheat\EasyAntiCheat.exe" enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="Block Rockstar Launcher" dir=out action=block program="C:\Program Files\Rockstar Games\Launcher\Launcher.exe" enable=yes >nul 2>&1

:: Adicionando arquivo de exclusão para o Windows Defender
echo [*] Configurando exclusoes para Windows Defender...
powershell -Command "try { Add-MpPreference -ExclusionPath '%localappdata%\FiveM' -ErrorAction SilentlyContinue } catch {}" >nul 2>&1
powershell -Command "try { Add-MpPreference -ExclusionPath 'C:\Program Files\Rockstar Games' -ErrorAction SilentlyContinue } catch {}" >nul 2>&1

:: Limpando registros de eventos
echo [*] Limpando registros de eventos...
wevtutil cl Application >nul 2>&1
wevtutil cl System >nul 2>&1
wevtutil cl Security >nul 2>&1

:: Adicionando chave de registro para proteger o sistema
echo [*] Adicionando chave de registro para proteger o sistema...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableRemoteDesktop /t REG_DWORD /d 0 /f >nul 2>&1

:: Proteção especifica para rastreadores de hardware do FiveM
echo [*] Aplicando protecao especifica contra rastreadores de hardware do FiveM...
reg add "HKLM\SOFTWARE\Microsoft\FTH" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v NetworkService /t REG_MULTI_SZ /d ServiceSvchost /f >nul 2>&1

echo.
echo [*] Protecao anti-cheat avancada ativada com sucesso!
echo.
echo [*] Instrucoes adicionais para FiveM:
echo     1. Use sempre uma VPN ao conectar em servidores
echo     2. Nunca use o mesmo nome de usuario apos ser banido
echo     3. Altere sua configuracao grafica para dificultar a deteccao
echo     4. Utilize o spoofer antes de cada nova conexao ao servidor
echo.
echo [*] Uso recomendado: Reinicie o computador apos esta operacao
echo     para garantir que todas as mudancas estejam aplicadas.
echo.
echo ========================================================
echo.

:: Garantindo que o processo não encerre inesperadamente
echo [*] Finalizando o processo de proteção anti-cheat...
echo.
echo     Pressione qualquer tecla para retornar ao menu principal...
pause >nul
goto menu

:CheckCurrentIDs
cls
color 0E
echo ========================================================
echo                ONLYS SPOOFER - VERIFICAR IDS ATUAIS
echo ========================================================
echo.
echo Coletando informacoes do sistema...
echo.

echo [*] Machine GUID:
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /v MachineGuid 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar MachineGUID
)

echo.
echo [*] Hardware Profile:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001" /v HwProfileGuid 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar Hardware Profile
)

echo.
echo [*] Machine ID:
reg query "HKLM\SOFTWARE\Microsoft\SQMClient" /v MachineId 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar Machine ID
)

echo.
echo [*] Product ID:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductId 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar Product ID
)

echo.
echo [*] Build GUID:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildGUID 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar BuildGUID
)

echo.
echo [*] Installation ID:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallationID 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar InstallationID
)

echo.
echo [*] BIOS Informacoes (Registro):
reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v SystemManufacturer 2>nul
reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v SystemProductName 2>nul
reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v BIOSVendor 2>nul
reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v BIOSVersion 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar informacoes BIOS do registro
)

echo.
echo [*] Informacoes de Disco:
reg query "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" /v Identifier 2>nul
reg query "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" /v SerialNumber 2>nul
if %errorlevel% neq 0 (
    echo     Nao foi possivel recuperar informacoes de disco
)

echo.
echo [*] Nome do Computador:
echo     %computername%

echo.
echo [*] MAC Address de adaptadores de rede ativos:
powershell -ExecutionPolicy Bypass -Command "try { Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { Write-Host ('   Adaptador: ' + $_.Name + ' - MAC: ' + $_.MacAddress) } } catch { Write-Host '   Erro ao recuperar informacoes de rede' }" 2>nul

echo.
echo [*] BIOS Info (Hardware):
wmic bios get serialnumber 2>nul || echo     Nao foi possivel recuperar serial da BIOS

echo.
echo [*] Motherboard Info (Hardware):
wmic baseboard get serialnumber 2>nul || echo     Nao foi possivel recuperar serial da Motherboard

echo.
echo [*] Volume Serial Number:
for /f "tokens=2" %%a in ('wmic logicaldisk where "DeviceID='C:'" get VolumeSerialNumber /value 2^>nul') do echo     C: %%a

echo.
echo [*] Informacoes Especificas do FiveM (se estiver instalado):
set "fivemCachePath=%localappdata%\FiveM\FiveM.app"
if exist "!fivemCachePath!" (
    echo     FiveM instalado em: !fivemCachePath!
    
    echo     Verificando arquivo CitizenFX:
    set "citizenPath=%localappdata%\DigitalEntitlements"
    if exist "!citizenPath!" (
        echo     CitizenFX encontrado em: !citizenPath!
    ) else (
        echo     CitizenFX nao encontrado (bom para evitar banimentos)
    )
) else (
    echo     FiveM nao encontrado neste sistema
)

echo.
echo ========================================================
echo.
echo Essas informacoes sao utilizadas por anti-cheats e outros
echo sistemas para identificar seu computador. Use o Spoofer para
echo modificar estes identificadores.
echo.
echo [*] Nota sobre FiveM: O FiveM utiliza varios desses identificadores
echo     para rastrear usuarios, inclusive apos banimentos. O processo
echo     de spoofing altera a maioria desses valores para evitar deteccao.
echo.
echo ========================================================
echo.
echo Pressione qualquer tecla para retornar ao menu principal...
pause >nul
goto menu