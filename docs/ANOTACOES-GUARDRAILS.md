# Anotações: guardrails para o MCP

## Resumo do projeto

Este projeto implementa um servidor MCP em Python com FastMCP. O fluxo de
autenticação apresenta uma página de login, encaminha as credenciais a um
serviço externo, valida a sessão e, para usuários `master`, inicia um desafio
MFA. Após o login, o cliente MCP usa um identificador de sessão opaco no
header `X-Auth-Session-ID` (configurável).

As sessões upstream e os cookies correspondentes são armazenados no MongoDB
com criptografia AES-GCM. O middleware procura a sessão e consulta o serviço
de validação em cada requisição MCP antes de permitir que ela prossiga.

As ferramentas `hello_world`, `get_my_notes` e `add_note` em `main.py` são
exemplos/rascunhos: não leem nem gravam notas de verdade e não chamam uma API
de negócio. Portanto, guardrails de autorização por usuário, confirmação de
ações e proteção de dados precisam ser definidos antes de conectar operações
reais.

## O que significa guardrail neste MCP

Um guardrail é uma regra técnica ou operacional que limita o que o MCP pode
fazer e em quais condições. Ele deve reduzir o impacto de uma chamada
incorreta, abusiva ou ambígua. Exemplos: validar a identidade em cada
requisição, restringir quais registros o usuário pode acessar, impor limites
de tamanho e exigir confirmação antes de uma ação destrutiva.

Autenticação responde “quem está chamando?”. Autorização e guardrails
respondem “o que essa pessoa e esta ferramenta podem fazer, com quais dados e
sob quais limites?”.

## Guardrails já presentes no código

- **Validação de sessão no acesso MCP:** o middleware exige o identificador
  configurado no header, rejeita identificadores ausentes ou longos demais,
  recupera a sessão e chama o serviço de validação antes de continuar.
- **Verificação de MFA:** a sessão de `master` é rejeitada enquanto o serviço
  de validação não informar `mfa_verified: true`. O aplicativo inicia o
  desafio, mas a integração atual não coleta nem envia o código MFA; essa
  etapa depende do serviço externo.
- **Proteção dos dados da sessão:** o identificador é opaco; o MongoDB usa o
  hash do identificador como chave, e os cookies upstream são cifrados com
  AES-GCM. A sessão tem expiração e índice TTL. A chave de criptografia deve
  decodificar para 32 bytes.
- **Limites e chamadas externas:** há limites configurados para corpos de
  requisição e respostas externas, timeout para chamadas de autenticação e
  redirecionamentos HTTP desativados. URLs dos serviços de autenticação
  precisam usar HTTPS, exceto localhost/loopback.
- **Erros esperados:** falhas de autenticação, validação, armazenamento e
  serviço externo são convertidas em respostas explícitas.

Esses controles são uma base, não uma garantia completa. Os testes atuais
concentram-se no armazenamento da sessão; a documentação do projeto informa
que testes de integração com os serviços externos e MongoDB real ainda não
estão incluídos.

## Guardrails recomendados

### Prioridade 1 — antes de implementar ferramentas de negócio

1. **Autorização em cada ferramenta**
   - Obtenha o principal autenticado pelo contexto da requisição; não aceite
     `user_id`, `user_type` ou permissões fornecidos como argumento pela
     chamada do modelo.
   - Defina permissões explícitas por ferramenta e por papel. Use bloqueio por
     padrão: papel, permissão ou identidade desconhecidos devem resultar em
     recusa.
   - Em consultas e alterações, filtre os dados pelo `user_id` validado no
     servidor. Não confie apenas em um identificador de registro enviado pelo
     cliente.
   - Reavalie as permissões também no serviço/API de negócio; não trate o MCP
     como a única fronteira de autorização.

2. **Validação estrita dos argumentos**
   - Para cada ferramenta, defina tipos, campos permitidos, tamanhos máximos,
     formatos e limites de quantidade. Rejeite campos inesperados quando
     apropriado.
   - Normalize entradas antes de usá-las e use consultas parametrizadas.
     Nunca concatene texto recebido em SQL, comandos, caminhos ou URLs.
   - Restrinja buscas a filtros e ordenações conhecidos; limite o número de
     resultados e o tamanho total da resposta.

3. **Confirmação e controle de efeitos colaterais**
   - Separe operações de leitura das de escrita. Uma operação de leitura não
     deve alterar estado.
   - Para exclusões, alterações em lote, envio externo ou outras ações de
     alto impacto, exija uma confirmação explícita em uma etapa separada.
     Mostre o alvo e o efeito previsto antes de executar.
   - Implemente modo de prévia (“dry run”) quando viável. Não interprete uma
     resposta ambígua como consentimento.
   - Use chaves de idempotência ou verificações de duplicidade para evitar
     repetir uma operação quando o cliente tentar novamente após timeout.

4. **Proteção contra acesso cruzado**
   - Verifique propriedade/acesso ao objeto no servidor em toda leitura,
     alteração e exclusão; não exponha se um recurso de outro usuário existe.
   - Teste explicitamente que um usuário não consegue consultar ou alterar
     recursos de outro usuário, inclusive mudando IDs nos argumentos.

### Prioridade 2 — proteger o serviço em execução

5. **Login, MFA e sessões**
   - Aplique limitação de tentativas no endpoint de login, com atraso
     progressivo e proteção contra brute force. Considere limites por conta e
     por origem sem permitir que terceiros bloqueiem facilmente uma conta.
   - Complete e teste o fluxo de verificação MFA com o serviço responsável;
     não habilite as ferramentas privilegiadas enquanto a verificação não
     estiver concluída.
   - Mantenha TTL curto o suficiente para o risco da aplicação, possibilite
     revogação de sessões e invalide sessões quando o serviço upstream ou a
     política de acesso exigir.
   - Trate o identificador de sessão como uma senha: nunca o registre,
     compartilhe ou coloque em prompts, screenshots ou repositórios.

6. **Limites de uso e disponibilidade**
   - Além dos limites de tamanho existentes, configure rate limits por
     usuário/sessão e por ferramenta, limites de concorrência e cotas para
     operações caras.
   - Defina limites também para respostas de ferramentas e paginação; evite
     devolver documentos, listas ou dados pessoais sem limite.
   - Use timeouts e, quando apropriado, circuit breaker nas APIs de negócio.
     Falha do serviço deve falhar de forma fechada: não conceder acesso com
     base em cache vencido ou em uma resposta de validação indisponível.

7. **Redes, transporte e superfície exposta**
   - Use HTTPS para todo acesso fora da máquina local. Restrinja a rede de
     saída às APIs necessárias, incluindo os serviços de autenticação e o
     banco.
   - Garanta que o middleware cubra todos os caminhos MCP publicados. Não
     exponha uma rota alternativa sem a mesma autenticação e autorização.
   - Restrinja o acesso ao endpoint de login e aplique proteção apropriada
     contra abuso. Revise cabeçalhos de segurança e política de origem para a
     página de login, especialmente se ela ficar acessível publicamente.
   - Configure MongoDB com TLS, usuário de privilégio mínimo, rede restrita,
     backups protegidos e política de retenção. Separe banco e chave de
     criptografia por ambiente.

8. **Segredos e configuração por ambiente**
   - Guarde tokens, URI do MongoDB e chave AES em um secret manager ou
     mecanismo seguro de implantação; não os inclua em código, `.vscode/mcp.json`,
     logs ou artefatos de build.
   - Separe credenciais, banco, chave e URLs de local, homologação e produção.
     Em produção, valide a configuração obrigatória no startup e interrompa a
     inicialização se houver valor ausente ou inseguro.
   - Não use contas, sessões, chaves ou dados reais de produção em testes e
     homologação. Restrinja quem pode alterar as variáveis de produção.

### Prioridade 3 — auditoria e manutenção

9. **Logs e auditoria sem segredos**
   - Registre ferramenta, horário, resultado, duração, ambiente e um
     identificador de correlação. Identifique o usuário com um ID interno
     minimizado, conforme a política de privacidade.
   - Não registre senhas, headers de sessão, cookies, tokens bearer, corpos
     completos ou respostas com dados pessoais.
   - Registre recusas de autorização, erros de validação e operações
     privilegiadas; proteja os logs contra alteração e limite seu acesso e
     retenção.

10. **Testes e implantação controlada**
    - Adicione testes unitários para autenticação e autorização de cada
      ferramenta, campos inválidos, limites, MFA pendente, expiração,
      revogação, repetição de operações e acesso cruzado entre usuários.
    - Adicione testes de integração em ambiente isolado para o contrato dos
      serviços de login, validação, MFA, MongoDB e APIs de negócio.
    - Exija revisão de código e verificações automatizadas antes da
      implantação. Faça primeiro rollout em homologação, com contas e dados
      fictícios; promova para produção com plano de rollback.
    - Monitore taxa de erro, latência, recusas, limite de chamadas e
      indisponibilidade dos serviços dependentes. Defina responsáveis e
      procedimento de resposta a incidente.

## Checklist curto antes de produção

- [ ] As ferramentas reais usam principal validado pelo servidor e autorização
      explícita por operação.
- [ ] Recursos são sempre isolados pelo usuário/tenant; há testes contra
      acesso cruzado.
- [ ] Escritas e exclusões têm validação, idempotência e confirmação adequada.
- [ ] O fluxo MFA está completo e bloqueia acesso privilegiado até a
      verificação upstream.
- [ ] Login, ferramentas e APIs de negócio têm limites de uso e tamanho.
- [ ] HTTPS, controle de rede, MongoDB restrito e segredos separados por
      ambiente estão configurados.
- [ ] Logs não contêm credenciais, cookies ou identificadores de sessão.
- [ ] Testes de integração, monitoramento, backup e rollback foram verificados.

## Referências no projeto

- `src/test_mcp_2/main.py`: composição do servidor e ferramentas de exemplo.
- `src/test_mcp_2/mfa_auth.py`: configuração, login, validação upstream e
  middleware de autenticação.
- `src/test_mcp_2/session_manager.py`: armazenamento, criptografia e expiração
  das sessões.
- `src/test_mcp_2/auth_errors.py`: erros de autenticação e respostas HTTP.
- `tests/test_session_manager.py`: testes atuais de persistência e integridade
  das sessões.
- `README.md`: fluxo de autenticação, configuração e limitações de integração.
