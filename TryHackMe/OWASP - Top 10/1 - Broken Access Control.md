# O que é?
Broken access control consiste em más configurações por parte de um website permitindo a um atacante aceder a partes do site que não era suposto poder.

# Exemplo
Por exemplo, dás login com uma conta de um banco e o URL fica alguma coisa tipo isto:
```
https://bank.thm/account?id=111111
```
![[Pasted image 20250521163841.png]]
Nada impede a um atacante de trocar o id=111111 para algo diferente:
```
https://bank.thm/account?id=222222
```
![[Pasted image 20250521163933.png]]
O que pode (**e deve**) acontecer num site bem configurado é que o atacante é barrado já que o id com que se autenticou e o id que está a aceder não são os mesmo.