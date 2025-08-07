# AWS 自动化补丁管理和报告系统

一个简单易用的 AWS 自动化解决方案，用于漏洞扫描、补丁管理和合规报告。

## 🎯 系统概述

这个解决方案帮助您：
1. **自动扫描漏洞** - 使用 AWS Inspector 检测安全漏洞
2. **下载补丁** - 自动下载可用的安全补丁（但不自动安装）
3. **系统审计** - 收集服务器运行状态和软件信息
4. **补丁审批** - 手动或自动审批补丁安装
5. **安全安装** - 只安装经过审批的补丁

## 🏗️ 系统架构图

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS Inspector │    │  补丁管理器     │    │  自定义脚本     │
│   (漏洞检测)    │    │  (仅下载模式)   │    │  (审计和报告)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  审批工作流     │
                    │  (手动/自动)    │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  补丁管理器     │
                    │  (安装模式)     │
                    └─────────────────┘
```

## 📁 项目文件结构

```
AWS-Automation-Patching-and-Reporting/
├── cloudformation/           # 基础设施代码
│   ├── main-stack.yaml      # 主要 CloudFormation 模板
│   ├── inspector-stack.yaml # Inspector 配置
│   └── patch-stack.yaml     # 补丁管理器设置
├── scripts/                  # 自动化脚本
│   ├── python/              # Python 自动化脚本
│   │   ├── inspector_handler.py
│   │   ├── patch_approver.py
│   │   └── compliance_reporter.py
│   └── powershell/          # PowerShell 脚本
│       ├── audit_services.ps1
│       ├── patch_inventory.ps1
│       └── compliance_check.ps1
├── lambda/                   # Lambda 函数
│   ├── inspector_processor/
│   ├── patch_approver/
│   └── compliance_reporter/
├── templates/                # SSM 文档模板
│   ├── audit-document.yaml
│   └── patch-document.yaml
└── docs/                     # 文档
    ├── deployment-guide.md
    └── troubleshooting.md
```

## 🚀 快速开始

### 前置要求

- AWS 账户（需要管理员权限）
- 安装了 AWS CLI 的电脑
- Python 3.8+ 
- PowerShell 5.1+（Windows 服务器需要）
- 目标服务器已安装 AWS Systems Manager 代理

### 部署步骤

#### 步骤 1: 准备环境
1. **下载项目文件**
   ```bash
   git clone https://github.com/your-org/aws-automation-patching-and-reporting.git
   cd aws-automation-patching-and-reporting
   ```

2. **配置 AWS 凭据**
   ```bash
   aws configure
   # 输入您的 AWS 访问密钥 ID
   # 输入您的 AWS 秘密访问密钥
   # 输入您的默认区域（例如：us-east-1）
   # 输入您的默认输出格式（json）
   ```

#### 步骤 2: 一键部署
使用我们提供的简单部署脚本：

```powershell
# Windows PowerShell
.\deploy.ps1 -Environment dev -NotificationEmail admin@yourcompany.com

# 或者使用更多选项
.\deploy.ps1 -Environment prod -NotificationEmail admin@yourcompany.com -S3BucketName "my-patching-reports" -OperatingSystem "WINDOWS"
```

#### 步骤 3: 配置目标服务器
1. **为服务器添加标签**
   ```bash
   aws ec2 create-tags --resources i-1234567890abcdef0 --tags Key=PatchGroup,Value=dev-servers
   ```

2. **确保服务器已安装 Systems Manager 代理**
   - Windows 服务器通常已预装
   - Linux 服务器需要手动安装

## 🔧 配置说明

### 补丁审批工作流

系统支持两种审批方式：

**手动审批（推荐用于生产环境）：**
- 系统会发送邮件通知您有补丁需要审批
- 您可以在 AWS 控制台或 S3 中查看补丁详情
- 手动选择要安装的补丁
- 系统只安装您批准的补丁

**自动审批（适用于开发环境）：**
- 系统根据安全等级自动审批补丁
- 高严重性漏洞（CVSS ≥ 8.0）自动批准
- 低风险补丁需要手动审批

### 自定义设置

编辑 `config/patch-config.json` 文件来调整：
- 自动审批的安全等级阈值
- 要包含/排除的补丁类型
- 审批工作流设置
- 报告生成时间表

## 📊 监控和报告

### 可用报告

1. **漏洞报告** - Inspector 发现的漏洞及严重程度
2. **补丁合规报告** - 已安装 vs 可用补丁对比
3. **服务审计报告** - 运行服务和软件清单
4. **审批工作流报告** - 补丁审批/拒绝历史

### 查看报告

报告存储在 S3 中，可以通过以下方式访问：
- AWS 控制台（S3 存储桶）
- QuickSight 仪表板
- Athena 查询
- API 端点

## 🔒 安全特性

- 所有 IAM 角色遵循最小权限原则
- 补丁安装需要明确授权
- 所有活动都记录在 CloudTrail 中
- 敏感数据在存储和传输时都进行加密

## 🛠️ 故障排除

常见问题及解决方案：

### 1. Systems Manager 代理无响应
```bash
# Windows 检查代理状态
Get-Service -Name AmazonSSMAgent

# Linux 检查代理状态
sudo systemctl status amazon-ssm-agent
```

### 2. 找不到补丁基线
```bash
# 列出可用的补丁基线
aws ssm describe-patch-baselines

# 验证基线关联
aws ssm describe-patch-groups
```

### 3. Lambda 函数错误
```bash
# 检查 CloudWatch 日志
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/PatchingAutomation"
```

## 📝 许可证

MIT 许可证 - 详见 LICENSE 文件。

## 🤝 贡献

1. Fork 本仓库
2. 创建功能分支
3. 进行您的更改
4. 添加测试
5. 提交拉取请求

## 📞 支持

如有问题和疑问：
- 在本仓库中创建 issue
- 查看故障排除指南
- 查看 AWS Inspector 和补丁管理器文档

## 🎯 使用场景

### 场景 1: 开发环境
- 使用自动审批工作流
- 快速部署安全补丁
- 减少手动干预

### 场景 2: 生产环境
- 使用手动审批工作流
- 严格控制补丁安装
- 详细的变更记录

### 场景 3: 合规要求
- 生成详细的合规报告
- 支持 CIS、NIST、SOX 等标准
- 完整的审计跟踪

## 💡 最佳实践

1. **测试环境先行** - 先在开发环境测试补丁
2. **定期审查** - 定期检查补丁审批历史
3. **监控成本** - 关注 AWS 服务使用成本
4. **备份配置** - 定期备份配置文件
5. **安全审查** - 定期进行安全审查 