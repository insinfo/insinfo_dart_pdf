# Script para instalar a cadeia de certificados de teste no Windows
# Requer execução como Administrador para instalar no store de máquina
# Ou pode ser executado como usuário normal para instalar apenas no store do usuário
#
# IMPORTANTE: Este script SEMPRE remove certificados de teste antigos antes de instalar novos
# para evitar conflitos de certificados com o mesmo DN mas chaves diferentes.

param(
    [switch]$Machine,  # Instalar no store da máquina (requer admin)
    [switch]$Remove,   # Remover os certificados em vez de instalar
    [switch]$SkipCleanup # Pular a limpeza de certificados antigos (não recomendado)
)

$ErrorActionPreference = "Stop"

$p7bPath = "C:\MyDartProjects\insinfo_dart_pdf\test\tmp\Cadeia_Test-der.p7b"
$tempDir = "C:\MyDartProjects\insinfo_dart_pdf\test\tmp"

# Nomes dos certificados de teste para limpeza
$testCertNames = @(
    "Teste Autoridade Certificadora Raiz Brasileira v1",
    "Teste AC Intermediaria do Governo Federal do Brasil v1",
    "Teste AC Final do Governo Federal do Brasil v1",
    "Isaque Neves Sant Ana"
)

# Cores para output
function Write-Success { param($msg) Write-Host $msg -ForegroundColor Green }
function Write-Info { param($msg) Write-Host $msg -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host $msg -ForegroundColor Yellow }

# Função para remover certificados de teste antigos
function Remove-OldTestCertificates {
    param($StoreLocation)
    
    Write-Warn "=== REMOVENDO CERTIFICADOS DE TESTE ANTIGOS ==="
    Write-Host ""
    
    foreach ($certName in $testCertNames) {
        # Tentar remover do store Root
        try {
            $result = & certutil -delstore -user Root $certName 2>&1
            if ($LASTEXITCODE -eq 0 -and $result -match "Excluindo") {
                Write-Success "Removido do Root: $certName"
            }
        } catch { }
        
        # Tentar remover do store CA
        try {
            $result = & certutil -delstore -user CA $certName 2>&1
            if ($LASTEXITCODE -eq 0 -and $result -match "Excluindo") {
                Write-Success "Removido do CA: $certName"
            }
        } catch { }
    }
    
    # Remover também certificados com O=Gov-Br (versões antigas)
    $oldOrgNames = @("Gov-Br", "ICP-Brasil")
    foreach ($org in $oldOrgNames) {
        try {
            # Usar certutil para listar e remover
            $certs = & certutil -store -user CA 2>&1 | Select-String -Pattern "O=$org.*Teste"
            # Silenciosamente ignorar erros aqui
        } catch { }
    }
    
    Write-Host ""
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Magenta
Write-Host "  Instalador de Cadeia de Certificados  " -ForegroundColor Magenta
Write-Host "=========================================" -ForegroundColor Magenta
Write-Host ""

# Verificar se o arquivo P7B existe
if (-not (Test-Path $p7bPath)) {
    Write-Host "ERRO: Arquivo P7B nao encontrado: $p7bPath" -ForegroundColor Red
    Write-Host "Execute primeiro os testes para gerar a cadeia:" -ForegroundColor Yellow
    Write-Host "  dart test test/expanded_scenarios_test.dart" -ForegroundColor White
    exit 1
}

Write-Info "Arquivo P7B encontrado: $p7bPath"

# Determinar o store de destino
if ($Machine) {
    $storeLocation = "LocalMachine"
    Write-Warn "Instalando no store da MAQUINA (requer privilégios de administrador)"
    
    # Verificar se está rodando como admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERRO: Este modo requer execução como Administrador!" -ForegroundColor Red
        Write-Host "Execute o PowerShell como Administrador e tente novamente." -ForegroundColor Yellow
        exit 1
    }
} else {
    $storeLocation = "CurrentUser"
    Write-Info "Instalando no store do USUARIO ATUAL"
}

# Extrair certificados do P7B usando certutil
Write-Info "Extraindo certificados do P7B..."

# Usar certutil para converter P7B para certificados individuais
$certsDir = Join-Path $tempDir "extracted_certs"
if (Test-Path $certsDir) {
    Remove-Item -Path $certsDir -Recurse -Force
}
New-Item -ItemType Directory -Path $certsDir -Force | Out-Null

# Salvar o diretório atual e mudar para tempDir para evitar lixo na raiz do projeto
$originalDir = Get-Location
Set-Location $tempDir

# Exportar certificados do P7B (certutil -split gera arquivos no diretório atual)
$certutilOutput = & certutil -split -dump $p7bPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Set-Location $originalDir
    Write-Host "ERRO ao extrair certificados: $certutilOutput" -ForegroundColor Red
    exit 1
}

# Voltar ao diretório original
Set-Location $originalDir

# Carregar o P7B diretamente usando .NET
Write-Info "Carregando cadeia de certificados..."

try {
    # Ler o arquivo P7B
    $p7bBytes = [System.IO.File]::ReadAllBytes($p7bPath)
    
    # Criar uma coleção de certificados a partir do P7B
    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $collection.Import($p7bBytes)
    
    Write-Success "Encontrados $($collection.Count) certificados na cadeia"
    Write-Host ""
    
    # Listar os certificados encontrados
    $certIndex = 1
    foreach ($cert in $collection) {
        Write-Host "[$certIndex] $($cert.Subject)" -ForegroundColor White
        Write-Host "    Emissor: $($cert.Issuer)" -ForegroundColor Gray
        Write-Host "    Validade: $($cert.NotBefore.ToString('yyyy-MM-dd')) ate $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
        
        # Verificar se é auto-assinado (Root CA)
        $isSelfSigned = $cert.Subject -eq $cert.Issuer
        if ($isSelfSigned) {
            Write-Host "    Tipo: ROOT CA (auto-assinado)" -ForegroundColor Yellow
        }
        Write-Host ""
        $certIndex++
    }
    
    if ($Remove) {
        # Modo de remocao
        Write-Warn "=== MODO DE REMOCAO ==="
        Write-Host ""
        
        foreach ($cert in $collection) {
            $isSelfSigned = $cert.Subject -eq $cert.Issuer
            
            if ($isSelfSigned) {
                # Root CA vai para Trusted Root Certification Authorities
                $storeName = "Root"
            } else {
                # Intermediários vão para Intermediate Certification Authorities
                $storeName = "CA"
            }
            
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                
                # Procurar o certificado pelo thumbprint
                $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                
                if ($found) {
                    $store.Remove($cert)
                    Write-Success "Removido: $($cert.Subject)"
                } else {
                    Write-Warn "Nao encontrado no store: $($cert.Subject)"
                }
                
                $store.Close()
            } catch {
                Write-Host "ERRO ao remover $($cert.Subject): $_" -ForegroundColor Red
            }
        }
        
        Write-Host ""
        Write-Success "=== REMOCAO CONCLUIDA ==="
        
    } else {
        # Modo de instalação
        
        # SEMPRE remover certificados antigos antes de instalar (a menos que -SkipCleanup)
        if (-not $SkipCleanup) {
            Remove-OldTestCertificates -StoreLocation $storeLocation
        }
        
        Write-Info "=== INSTALANDO CERTIFICADOS ==="
        Write-Host ""
        
        foreach ($cert in $collection) {
            $isSelfSigned = $cert.Subject -eq $cert.Issuer
            
            if ($isSelfSigned) {
                # Root CA vai para Trusted Root Certification Authorities
                $storeName = "Root"
                $storeDesc = "Autoridades de Certificacao Raiz Confiaveis"
            } else {
                # Intermediários vão para Intermediate Certification Authorities  
                $storeName = "CA"
                $storeDesc = "Autoridades de Certificacao Intermediarias"
            }
            
            Write-Info "Instalando em '$storeDesc'..."
            Write-Host "  Certificado: $($cert.Subject)" -ForegroundColor White
            
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                
                # Verificar se já existe
                $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                
                if ($existing) {
                    Write-Warn "  -> Ja existe no store (ignorando)"
                } else {
                    $store.Add($cert)
                    Write-Success "  -> Instalado com sucesso!"
                }
                
                $store.Close()
            } catch {
                Write-Host "  ERRO: $_" -ForegroundColor Red
            }
            Write-Host ""
        }
        
        Write-Host "=========================================" -ForegroundColor Green
        Write-Success "=== INSTALACAO CONCLUIDA ==="
        Write-Host "=========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Os certificados foram instalados no store do $storeLocation." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Para verificar no Adobe Reader/Foxit:" -ForegroundColor White
        Write-Host "  1. Feche e reabra o Adobe Reader/Foxit" -ForegroundColor Gray
        Write-Host "  2. Abra o PDF: test\tmp\out_scenario1_govbr_chain.pdf" -ForegroundColor Gray
        Write-Host "  3. Clique na assinatura para ver os detalhes" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Para remover os certificados depois:" -ForegroundColor Yellow
        Write-Host "  .\install_test_chain_windows.ps1 -Remove" -ForegroundColor White
        Write-Host ""
    }
    
} catch {
    Write-Host "ERRO ao processar certificados: $_" -ForegroundColor Red
    exit 1
}
