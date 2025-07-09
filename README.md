# VsServer - Gerenciador de Servidores SSH

![VsServer Logo](https://img.icons8.com/?size=100&id=2171&format=png&color=000000)

VsServer é uma aplicação desktop intuitiva e poderosa, desenvolvida em Python com `CustomTkinter`, projetada para simplificar o gerenciamento de servidores SSH. Com uma interface gráfica amigável, você pode facilmente administrar usuários, grupos, monitorar o espaço em disco, executar comandos personalizados e muito mais, tudo a partir de um único local.

## ✨ Funcionalidades

*   **Gerenciamento de Conexões SSH:**
    *   Adicione, edite e remova conexões de servidor SSH.
    *   Salve credenciais de login (com criptografia segura).
    *   Conecte-se rapidamente aos seus servidores favoritos.
*   **Administração de Usuários:**
    *   Crie e delete usuários no servidor.
    *   Defina senhas para novos usuários ou resete senhas existentes.
    *   Associe usuários a grupos específicos.
    *   Bloqueie e desbloqueie contas de usuário.
    *   Liste todos os usuários do sistema.
*   **Gerenciamento de Grupos:**
    *   Crie e delete grupos de usuários.
    *   Liste todos os grupos existentes no servidor.
*   **Monitoramento e Diagnóstico:**
    *   Verifique o espaço em disco disponível nos seus servidores.
    *   Monitore a atividade recente dos usuários (últimos logins).
*   **Comandos Personalizados:**
    *   Execute comandos SSH personalizados diretamente da interface.
    *   Visualize a saída dos comandos em tempo real.
*   **Backup e Restauração de Configurações:**
    *   Exporte suas configurações de conexão para um arquivo JSON.
    *   Importe configurações existentes para facilitar a migração ou o compartilhamento.
*   **Segurança:**
    *   Login de administrador para acesso à aplicação.
    *   Criptografia de senhas de conexão salvas usando `Fernet`.
    *   Registro de logs de todas as operações para auditoria.

## ⚙️ Configuração

As configurações de conexão são salvas automaticamente no arquivo `config.json`. Este arquivo é criptografado para proteger suas senhas salvas.

*   `config.json`: Armazena as informações das conexões de servidor (IP, usuário, nome, senha criptografada).
*   `encryption_key.key`: Chave de criptografia utilizada para proteger as senhas. **Mantenha este arquivo seguro e não o compartilhe!**
*   `logs_servidores.log`: Registra todas as operações e eventos importantes da aplicação.

## 🔒 Segurança

O VsServer foi projetado com a segurança em mente:

*   **Criptografia de Senhas:** As senhas de conexão são criptografadas usando `Fernet` antes de serem salvas no `config.json`.
*   **Login de Administrador:** Protege o acesso à aplicação.
*   **Logs de Auditoria:** Todas as ações são registradas para rastreabilidade.

**Recomendação:** Embora as senhas sejam criptografadas, é sempre uma boa prática evitar salvar senhas sensíveis diretamente em arquivos, se possível. Considere usar métodos de autenticação baseados em chaves SSH para maior segurança.

## 🤝 Contribuição

Contribuições são bem-vindas! Se você tiver sugestões de melhorias, relatórios de bugs ou quiser adicionar novas funcionalidades, sinta-se à vontade para abrir uma *issue* ou enviar um *pull request*.

## 📄 Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

Desenvolvido com ❤️ por [Vilmar Tuminskii](https://github.com/VilmarTuminskii)
