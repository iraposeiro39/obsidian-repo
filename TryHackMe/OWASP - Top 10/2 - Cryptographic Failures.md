# O que é?
Refere-se a qualquer tipo de vulnerabilidade que vem com não usar/mau uso de encriptação. Isto pode se dar como a falta de encriptação ou a utilização de métodos de encriptação inseguros (como [Base64](https://en.wikipedia.org/wiki/Base64)).

# Exemplo
## Email
Quando acedes à tua conta de email através do browser, é importante garantir que as comunicações entre ti e o servidor estão encriptadas. Desta forma, qualquer intruso que tente intercetar os pacotes da tua rede não conseguirá recuperar o conteúdo dos teus emails. Quando encriptamos o tráfego de rede entre o cliente e o servidor, referimo-nos normalmente a isto como encriptação dos dados em trânsito.

Como os teus emails estão armazenados num servidor gerido pelo teu fornecedor de serviço, também é desejável que esse fornecedor não consiga ler os emails dos seus clientes. Para esse fim, os emails podem também ser encriptados quando armazenados nos servidores. A isto chamamos encriptação dos dados em repouso.

## Flat-file database
Em ambientes de produção, é comum ver bases de dados configuradas em servidores dedicados a correr serviços como MySQL ou MariaDB. No entanto, também é possível armazenar bases de dados como ficheiros simples — estas são conhecidas como _flat-file databases_ (bases de dados em ficheiro plano), por estarem guardadas como um único ficheiro no disco. Esta abordagem é muito mais simples do que configurar um servidor de base de dados completo e pode ser usada em aplicações web mais pequenas.

Contudo, se o ficheiro da base de dados estiver armazenado dentro da raiz do site (ou seja, numa pasta acessível ao utilizador que se liga ao site), isso representa um risco. Qualquer pessoa pode descarregar esse ficheiro e aceder à base de dados no seu próprio computador, com acesso total aos dados. Isto constitui uma exposição de dados sensíveis.

### Desencriptado
Vamos imaginar que sacamos uma base de dados:
![[Pasted image 20250521185624.png]]
 
Dá para ver que é uma base de dados SQLite, por isso basta correr o cliente `sqlite3` com o ficheiro `example.db`
![[Pasted image 20250521185656.png]]

E com um bocadinho de conhecimento de SQL...
![[Pasted image 20250521185908.png]]

### "Encriptado"
Acima demonstrei uma base de dados sem qualquer tipo de encriptação, mas vamos imaginar que as passwords vêm encriptadas com uma hash bastante fraca, como [MD5](https://en.wikipedia.org/wiki/MD5).
Vamos usar a seguinte hash como exemplo:
```
5f4dcc3b5aa765d61d8327deb882cf99
```
Para métodos de encriptação mais sofisticados é necessário ferramentas mais envolvidas, para MD5, basta usar um site como [[Useful Websites#[CrackStation](https //crackstation.net/)|CrackStation]]:
![[Pasted image 20250521191959.png]]
GGs