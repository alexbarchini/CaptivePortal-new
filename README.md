# CaptivePortal-new

Portal externo para **Ruckus SmartZone (vSZ-H 6.1.x)** usando fluxo **Hotspot/WISPr + NBI (/portalintf)** e base local em PostgreSQL.

## Arquitetura resumida

1. SmartZone redireciona cliente para `GET /portal` com parâmetros WISPr (ex: `nbiIP`, `UE-IP`, `UE-MAC`, `url/orig_url`, `uip`, `client_mac`, etc).
2. Portal preserva e reaproveita todos os parâmetros na jornada login/cadastro.
3. Usuário autentica com `CPF + senha` (validação local no Postgres).
4. Portal chama NBI:
   - `POST https://{sz_management_ip}:9443/portalintf`
   - `RequestCategory=UserOnlineControl`
   - `RequestType=LoginAsync` (ou `Login`)
   - `UE-IP` e `UE-MAC` no formato recebido (inclusive `ENC...`)
5. Em `LoginAsync`, o portal faz polling `Status` até sucesso/falha (timeout padrão 18s).
6. Em sucesso: redireciona para `url`/`orig_url`.
7. SmartZone segue seu fluxo com RADIUS e Accounting (Check Point IA aprende `visitante_<cpf>` via 1813).

> O portal **não fala com o Check Point diretamente**.

---

## Estrutura

- `src/server.js` — app Express, rotas `/portal`, `/register`, `/login`, `/success`.
- `src/services/nbi.js` — integração NBI (`LoginAsync/Login` + `Status`).
- `src/utils/validators.js` — validações CPF, telefone, senha forte com Zod.
- `migrations/001_init.sql` — tabelas `users`, `lgpd_consents`, `auth_events`.
- `schema.sql` — espelho da migração inicial.
- `docker-compose.yml` — app + postgres + freeradius (opcional).

---

## Subir com Docker Compose

```bash
docker compose up --build
```

Serviços:
- App: `http://localhost:3000`
- Postgres: `localhost:5432`
- FreeRADIUS (opcional): UDP `1812/1813`

A aplicação roda migrações automaticamente ao iniciar.

---

## Variáveis importantes

Copie `.env.example` para `.env` e ajuste:

- `NBI_REQUEST_PASSWORD`: senha configurada em **Administration > External Services > WISPr Northbound Interface** na SmartZone.
- `SZ_MANAGEMENT_IP`: IP de management da controladora.
- `NBI_MOCK=true|false`: modo simulador sem SmartZone.
- `TERMS_VERSION` e `PRIVACY_VERSION`: versões dos documentos LGPD gravadas no consentimento.
- `USER_ACCOUNT_VALIDITY_DAYS`: validade da conta no portal em dias (default: `30`).
- `RENEW_ON_LOGIN=true|false`: renova automaticamente a validade da conta em login bem-sucedido (default: `true`).
- `LOG_TZ`: timezone dos logs estruturados (default: `America/Sao_Paulo`).
- `AUTH_LOG_FILE_PATH`: caminho do arquivo de log estruturado (default: `./logs/auth-process.log`).

---

## Rotas

### `GET /portal`
Landing/login. Aceita parâmetros de captive portal e os preserva em hidden fields.

Exemplo:

```text
/portal?nbiIP=10.10.10.5&UE-IP=ENCxxx&UE-MAC=ENCyyy&url=https%3A%2F%2Fexample.com&uip=192.168.100.10&client_mac=aa:bb:cc:dd:ee:ff
```

### `GET /register`
Form de cadastro com LGPD:
- Termos de Uso
- Política de Privacidade
- Autorização de tratamento para controle de acesso/auditoria

### `POST /register`
- valida CPF (dígitos + DV), telefone e senha forte
- gera `username_radius = visitante_<cpf>`
- hash de senha com Argon2
- define validade da conta em `now() + USER_ACCOUNT_VALIDITY_DAYS`
- grava consentimento LGPD com timestamp/IP/user-agent e versões dos termos

### `POST /login`
- valida CPF/senha no Postgres
- bloqueia login quando `users.expires_at < now()`
- pode renovar validade da conta ao autenticar (`RENEW_ON_LOGIN=true`)
- chama NBI com `UE-IP` e `UE-MAC` recebidos no redirect
- registra auditoria em `auth_events` com `raw_params_json`

---

## Log detalhado do processo de autenticação

Além da trilha em banco (`auth_events`), a aplicação grava em **stdout** e também em arquivo (`AUTH_LOG_FILE_PATH`, por padrão `./logs/auth-process.log`) uma linha por evento no formato:

```text
2026-02-26T16:00:39.261-03:00,{"level":"error","event":"login_attempt_failed",...}
```

Regras do formato:
- timestamp ISO-8601 com offset do timezone configurado (`LOG_TZ`) no início da linha
- vírgula após o timestamp
- JSON válido em linha única contendo `level`, `event` e payload
- sem chave `timestamp` dentro do JSON

Campos típicos no JSON:
- usuário/CPF informado
- origem da requisição (`request_ip`, `user_agent`)
- etapa do fluxo (`login_attempt_started`, `login_password_verified`, `login_attempt_nbi_result`, etc.)
- motivo do erro e stacktrace quando houver

Como acompanhar logs:
- `docker compose logs -f app` para acompanhar stdout da aplicação.
- arquivo persistente no host em `./logs/auth-process.log` (montado via volume `./logs:/app/logs`).

---

## Payload NBI (exemplo)

### LoginAsync

```json
{
  "Vendor": "ruckus",
  "RequestUserName": "external-portal",
  "RequestPassword": "<NBI_REQUEST_PASSWORD>",
  "APIVersion": "1.0",
  "RequestCategory": "UserOnlineControl",
  "RequestType": "LoginAsync",
  "UE-IP": "ENC...",
  "UE-MAC": "ENC...",
  "UE-Proxy": "0",
  "UE-Username": "visitante_12345678909",
  "UE-Password": "senha_digitada_no_form"
}
```

### Status (polling)

```json
{
  "Vendor": "ruckus",
  "RequestUserName": "external-portal",
  "RequestPassword": "<NBI_REQUEST_PASSWORD>",
  "APIVersion": "1.0",
  "RequestCategory": "UserOnlineControl",
  "RequestType": "Status",
  "UE-IP": "ENC...",
  "UE-MAC": "ENC..."
}
```

---

## SmartZone: checklist de configuração

1. Criar/ajustar WLAN com Hotspot (WISPr) e selecionar **External Portal** apontando para `https://<portal>/portal`.
2. Habilitar **WISPr Northbound Interface** e definir senha (`NBI_REQUEST_PASSWORD`).
3. Garantir redirect com parâmetros de cliente (`UE-IP`, `UE-MAC`, `url/orig_url`, etc.).
4. Walled garden:
   - liberar FQDN/IP do portal externo
   - liberar conectividade para `https://{sz_management_ip}:9443/portalintf` (se necessário conforme topologia)
5. Authentication Service -> RADIUS (ex: FreeRADIUS)
6. Accounting Service -> Check Point (1813)

---

## Testar sem SmartZone (modo simulador)

Com `NBI_MOCK=true` (ou query `mock=1`):

```text
http://localhost:3000/portal?mock=1&UE-IP=ENC_TEST_IP&UE-MAC=ENC_TEST_MAC&url=https%3A%2F%2Fexample.org
```

Nesse modo, o NBI retorna sucesso local e o usuário é redirecionado para `url`.

---

## Sobre FreeRADIUS no compose (opcional)

O serviço está no compose como base de laboratório. Em produção, ajuste:
- `clients.conf` com IP/secret corretos da SmartZone.
- módulo SQL para o esquema oficial do FreeRADIUS **ou** uma tabela dedicada `radcheck`.

### Trade-off de senha

Este portal armazena senha como **Argon2** para login web local (mais seguro). Para autenticação RADIUS PAP tradicional, o FreeRADIUS costuma precisar acesso a segredo verificável de forma compatível (`Cleartext-Password` ou hash suportado por módulo específico).

Opções comuns:
1. manter tabela RADIUS própria (`radcheck`) com `Cleartext-Password` (menos seguro, mais simples);
2. adaptar autenticação para método/hash suportado diretamente no FreeRADIUS;
3. separar totalmente login do portal e credenciais RADIUS.

---

## Validação no Check Point Identity Awareness

Após login bem-sucedido no portal + autorização NBI, a SmartZone deve gerar accounting para o Check Point. Verifique no IA a aparição do usuário `visitante_<cpf>` associado ao IP/MAC do cliente.
