```markdown
# EyesOf.py - Security Testing Toolkit

Ferramenta completa para testes de segurança, laboratórios vulneráveis e simulação de servidores para análise de segurança.

## 📦 Instalação

### Termux
```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/seu-usuario/EyesOf.py.git
cd EyesOf.py
python EyesOf.py
```

Linux

```bash
sudo apt update && sudo apt upgrade
sudo apt install python3 python3-pip git
git clone https://github.com/seu-usuario/EyesOf.py.git
cd EyesOf.py
python3 EyesOf.py
```

📋 Dependências

O script usa apenas bibliotecas padrão do Python:

· os, sys, socket, threading
· base64, hashlib, random, string
· subprocess, datetime

Nenhuma instalação adicional necessária!

🚀 Uso Rápido

```bash
python EyesOf.py
```

🔧 Funcionalidades Principais

🧪 Laboratórios de Teste

· Site Vulnerável - Ambiente controlado para testes
· Servidor FTP Fake - Simulação para análise de brute force
· Servidor SSH Fake - Ambiente para testes de autenticação
· Laboratório Flask - Aplicações web para testes

🔐 Ferramentas de Segurança

· Criptografia/Descriptografia de texto e arquivos
· Scanner de portas
· Geração de hashes (MD5, SHA1, SHA256)
· Gerador de senhas fortes
· Análise de rede e arquivos

🎯 Menu Principal

```
[1] Ferramentas de Segurança
[2] Laboratórios Vulneráveis  
[3] Servidores Fake
[0] Sair
```

⚠️ Aviso Legal

PARA FINS EDUCACIONAIS E ÉTICOS APENAS

· Use apenas em ambientes autorizados
· Não utilize para atividades maliciosas
· Desenvolvedores não se responsabilizam pelo uso indevido

🐛 Solução de Problemas

Erro de permissão no Termux:

```bash
chmod +x EyesOf.py
termux-setup-storage
```

Problema de encoding:

```bash
export PYTHONIOENCODING=utf-8
```

📞 Suporte

Report issues em: GitHub Issues

---

Use com responsabilidade! 🔒

```

Este README.md é:
- ✅ **Curto e direto** - apenas informações essenciais
- ✅ **Focado em comandos** - fácil de seguir
- ✅ **Sem bibliotecas externas** - destaca que usa apenas Python padrão
- ✅ **Com avisos legais** - importante para ferramentas de segurança
- ✅ **Organizado** - fácil de ler e usar
