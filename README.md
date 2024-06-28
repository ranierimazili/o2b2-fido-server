# o2b2-fido-server
Este projeto tem como intuito ser um servidor FIDO que siga os padrões definidos pelo Open Finance Brasil para a Jornada sem Redirecionamento.

Esta aplicação é uma implementação do [fido2-lib](https://github.com/webauthn-open-source/fido2-lib) com as customizações necessárias para atender aos critérios definidos pelo Open Finance Brasil para atendimento a Jornada sem Redirecionamento.

# Requisitos mínimos
Node >= 16

# Executando o projeto

Instale as dependências
```
npm install
```

Execute o projeto
```
npm run start
```

Após subir o serviço, ele está aguardando as requisições em https://localhost:4100.

A porta (4100) pode ser alterada através do arquivo [.env](./.env).

Os endpoints disponíveis estão documentados [aqui](apis_spec.yaml).

# TODO's
- Adicionar alternativas ao banco de dados (atualmente só suporta banco em memória "quick-lru")
- Adicionar método DELETE para o fido-registration
- Adicionar o retorno 404 nos métodos que busca o enrollmentID para casos onde o mesmo não existe mais
- Atrelar as autenticações ao consentID e não ao enrollmentID para não ter sobrescrita de autenticações (colisões)
    - Essa alteração deve ser realizada no método fido-sign-options e fido-sign
- Validar a utilização de userHandle no fido-sign-options
- Verificar se todos os dados que precisam ser trafegados estão em formato correto (base64url)
    - Ex: postFidoRegistrationOptions -> attestationOpts.user.id deve estar em base64url ou string
- Verificar se rp.id retornado em alguns métodos deve ser de fato a CN informada na requisição, considerando situações de instituições onde o CN não é uma URL (Android & iOS)

