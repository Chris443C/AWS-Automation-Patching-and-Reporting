# AWS 自动化补丁管理系统 - 一键部署脚本（中文版）
# 这个脚本帮助您轻松部署 AWS 自动化补丁管理解决方案

param(
    [Parameter(Mandatory=$true, HelpMessage="环境名称（例如：dev, prod）")]
    [string]$Environment,
    
    [Parameter(Mandatory=$true, HelpMessage="接收通知的邮箱地址")]
    [string]$NotificationEmail,
    
    [Parameter(Mandatory=$false, HelpMessage="S3 存储桶名称（可选）")]
    [string]$S3BucketName = "aws-patching-automation-reports",
    
    [Parameter(Mandatory=$false, HelpMessage="操作系统类型（WINDOWS 或 LINUX）")]
    [string]$OperatingSystem = "WINDOWS",
    
    [Parameter(Mandatory=$false, HelpMessage="补丁审批延迟天数（1-30天）")]
    [int]$PatchApprovalDelay = 7,
    
    [Parameter(Mandatory=$false, HelpMessage="跳过 Inspector 部署")]
    [switch]$SkipInspector = $false,
    
    [Parameter(Mandatory=$false, HelpMessage="跳过补丁管理器部署")]
    [switch]$SkipPatchManager = $false,
    
    [Parameter(Mandatory=$false, HelpMessage="仅显示将要执行的操作，不实际部署")]
    [switch]$DryRun = $false
)

# 设置错误处理
$ErrorActionPreference = "Stop"

# 颜色输出函数
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# 显示欢迎信息
function Show-WelcomeMessage {
    Write-ColorOutput "`n=== AWS 自动化补丁管理系统部署向导 ===" "Cyan"
    Write-ColorOutput "这个向导将帮助您部署完整的补丁管理解决方案" "White"
    Write-ColorOutput "包括漏洞扫描、补丁下载、审批工作流和自动安装" "White"
    Write-ColorOutput "==============================================`n" "Cyan"
}

# 检查 AWS CLI
function Test-AWSCLI {
    Write-ColorOutput "正在检查 AWS CLI..." "Yellow"
    try {
        $awsVersion = aws --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✓ AWS CLI 已安装: $awsVersion" "Green"
            return $true
        }
    }
    catch {
        Write-ColorOutput "✗ 未找到 AWS CLI" "Red"
        Write-ColorOutput "请先安装 AWS CLI:" "Yellow"
        Write-ColorOutput "Windows: https://awscli.amazonaws.com/AWSCLIV2.msi" "White"
        Write-ColorOutput "macOS: https://awscli.amazonaws.com/AWSCLIV2.pkg" "White"
        Write-ColorOutput "Linux: https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" "White"
        return $false
    }
}

# 检查 AWS 凭据
function Test-AWSCredentials {
    Write-ColorOutput "正在检查 AWS 凭据..." "Yellow"
    try {
        $identity = aws sts get-caller-identity 2>&1 | ConvertFrom-Json
        if ($identity) {
            Write-ColorOutput "✓ AWS 凭据有效，账户: $($identity.Account)" "Green"
            Write-ColorOutput "  用户: $($identity.Arn)" "Gray"
            return $true
        }
    }
    catch {
        Write-ColorOutput "✗ AWS 凭据无效或未配置" "Red"
        Write-ColorOutput "请运行以下命令配置凭据:" "Yellow"
        Write-ColorOutput "aws configure" "White"
        Write-ColorOutput "然后输入您的 AWS 访问密钥和秘密密钥" "White"
        return $false
    }
}

# 验证配置文件
function Test-Configuration {
    Write-ColorOutput "正在验证配置文件..." "Yellow"
    
    # 检查配置文件
    if (-not (Test-Path "config/patch-config.json")) {
        Write-ColorOutput "✗ 配置文件未找到: config/patch-config.json" "Red"
        return $false
    }
    
    # 检查 CloudFormation 模板
    $templates = @(
        "cloudformation/main-stack.yaml",
        "cloudformation/inspector-stack.yaml",
        "cloudformation/patch-stack.yaml"
    )
    
    foreach ($template in $templates) {
        if (-not (Test-Path $template)) {
            Write-ColorOutput "✗ CloudFormation 模板未找到: $template" "Red"
            return $false
        }
    }
    
    Write-ColorOutput "✓ 配置文件验证通过" "Green"
    return $true
}

# 更新配置文件
function Update-Configuration {
    Write-ColorOutput "正在更新配置文件..." "Yellow"
    
    try {
        $config = Get-Content "config/patch-config.json" | ConvertFrom-Json
        $config.environment = $Environment
        
        # 更新通知设置
        $config.notifications.email.recipients[0] = $NotificationEmail
        
        # 更新 S3 存储桶名称
        $config.reporting.s3Bucket = $S3BucketName
        
        # 保存配置
        $config | ConvertTo-Json -Depth 10 | Set-Content "config/patch-config.json"
        
        Write-ColorOutput "✓ 配置文件已更新" "Green"
    }
    catch {
        Write-ColorOutput "✗ 更新配置文件时出错: $_" "Red"
        return $false
    }
}

# 部署 CloudFormation 堆栈
function Deploy-CloudFormationStack {
    param(
        [string]$TemplateFile,
        [string]$StackName,
        [hashtable]$Parameters = @{}
    )
    
    Write-ColorOutput "正在部署: $StackName" "Yellow"
    
    if ($DryRun) {
        Write-ColorOutput "🔍 模拟模式: 将部署 $StackName" "Cyan"
        return $true
    }
    
    # 构建参数字符串
    $paramString = ""
    if ($Parameters.Count -gt 0) {
        $paramString = " --parameter-overrides"
        foreach ($key in $Parameters.Keys) {
            $paramString += " $key=$($Parameters[$key])"
        }
    }
    
    $command = "aws cloudformation deploy --template-file $TemplateFile --stack-name $StackName$paramString --capabilities CAPABILITY_NAMED_IAM"
    
    Write-ColorOutput "执行命令: $command" "Gray"
    
    try {
        Invoke-Expression $command
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✓ 成功部署 $StackName" "Green"
            return $true
        }
        else {
            Write-ColorOutput "✗ 部署 $StackName 失败" "Red"
            return $false
        }
    }
    catch {
        Write-ColorOutput "✗ 部署 $StackName 时出错: $_" "Red"
        return $false
    }
}

# 显示部署摘要
function Show-DeploymentSummary {
    Write-ColorOutput "`n=== 部署配置摘要 ===" "Cyan"
    Write-ColorOutput "环境: $Environment" "White"
    Write-ColorOutput "通知邮箱: $NotificationEmail" "White"
    Write-ColorOutput "S3 存储桶: $S3BucketName" "White"
    Write-ColorOutput "操作系统: $OperatingSystem" "White"
    Write-ColorOutput "补丁审批延迟: $PatchApprovalDelay 天" "White"
    Write-ColorOutput "跳过 Inspector: $SkipInspector" "White"
    Write-ColorOutput "跳过补丁管理器: $SkipPatchManager" "White"
    Write-ColorOutput "模拟模式: $DryRun" "White"
    Write-ColorOutput "========================`n" "Cyan"
}

# 显示部署结果
function Show-DeploymentResult {
    Write-ColorOutput "`n=== 部署完成！===" "Green"
    Write-ColorOutput "恭喜！您的 AWS 自动化补丁管理系统已成功部署。" "White"
    Write-ColorOutput "" "White"
    Write-ColorOutput "接下来的步骤:" "Yellow"
    Write-ColorOutput "1. 为您的服务器添加标签: PatchGroup=$Environment-servers" "White"
    Write-ColorOutput "2. 确保服务器已安装 Systems Manager 代理" "White"
    Write-ColorOutput "3. 订阅 SNS 通知邮件" "White"
    Write-ColorOutput "4. 测试系统功能" "White"
    Write-ColorOutput "5. 查看详细部署指南" "White"
    Write-ColorOutput "" "White"
    Write-ColorOutput "系统将自动:" "Yellow"
    Write-ColorOutput "• 每天扫描安全漏洞" "White"
    Write-ColorOutput "• 下载可用补丁" "White"
    Write-ColorOutput "• 发送通知邮件" "White"
    Write-ColorOutput "• 安装已审批的补丁" "White"
    Write-ColorOutput "• 生成合规报告" "White"
    Write-ColorOutput "" "White"
    Write-ColorOutput "如需帮助，请查看 docs/部署指南_中文.md" "Cyan"
    Write-ColorOutput "=============================" "Green"
}

# 主部署函数
function Start-Deployment {
    # 显示欢迎信息
    Show-WelcomeMessage
    
    # 显示部署摘要
    Show-DeploymentSummary
    
    # 验证前置条件
    Write-ColorOutput "`n正在检查前置条件..." "Yellow"
    
    if (-not (Test-AWSCLI)) {
        Write-ColorOutput "请先安装 AWS CLI，然后重新运行脚本" "Red"
        exit 1
    }
    
    if (-not (Test-AWSCredentials)) {
        Write-ColorOutput "请先配置 AWS 凭据，然后重新运行脚本" "Red"
        exit 1
    }
    
    if (-not (Test-Configuration)) {
        Write-ColorOutput "配置文件验证失败" "Red"
        exit 1
    }
    
    # 更新配置
    Update-Configuration
    
    # 部署主基础设施
    Write-ColorOutput "`n正在部署主基础设施..." "Yellow"
    $mainParams = @{
        "Environment" = $Environment
        "NotificationEmail" = $NotificationEmail
        "S3BucketName" = $S3BucketName
    }
    
    $mainSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/main-stack.yaml" -StackName "aws-patching-automation-$Environment" -Parameters $mainParams
    
    if (-not $mainSuccess) {
        Write-ColorOutput "主基础设施部署失败" "Red"
        exit 1
    }
    
    # 部署 Inspector（如果未跳过）
    if (-not $SkipInspector) {
        Write-ColorOutput "`n正在部署 AWS Inspector..." "Yellow"
        $inspectorParams = @{
            "Environment" = $Environment
            "EnableEC2Scanning" = "true"
            "EnableECRScanning" = "true"
            "EnableLambdaScanning" = "true"
        }
        
        $inspectorSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/inspector-stack.yaml" -StackName "aws-inspector-setup-$Environment" -Parameters $inspectorParams
        
        if (-not $inspectorSuccess) {
            Write-ColorOutput "Inspector 部署失败" "Red"
            exit 1
        }
    }
    else {
        Write-ColorOutput "跳过 Inspector 部署" "Yellow"
    }
    
    # 部署补丁管理器（如果未跳过）
    if (-not $SkipPatchManager) {
        Write-ColorOutput "`n正在部署补丁管理器..." "Yellow"
        $patchParams = @{
            "Environment" = $Environment
            "OperatingSystem" = $OperatingSystem
            "PatchApprovalDelay" = $PatchApprovalDelay.ToString()
        }
        
        $patchSuccess = Deploy-CloudFormationStack -TemplateFile "cloudformation/patch-stack.yaml" -StackName "aws-patch-manager-$Environment" -Parameters $patchParams
        
        if (-not $patchSuccess) {
            Write-ColorOutput "补丁管理器部署失败" "Red"
            exit 1
        }
    }
    else {
        Write-ColorOutput "跳过补丁管理器部署" "Yellow"
    }
    
    # 显示部署结果
    Show-DeploymentResult
}

# 执行部署
try {
    Start-Deployment
}
catch {
    Write-ColorOutput "部署过程中发生错误: $_" "Red"
    Write-ColorOutput "请检查错误信息并重试" "Yellow"
    exit 1
} 