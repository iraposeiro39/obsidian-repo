# O que é?
**Falhas de Injeção** são muito comuns em aplicações atuais e acontecem porque a aplicação interpreta dados fornecidos pelo utilizador como comandos ou parâmetros. Estas falhas variam conforme a tecnologia usada e como ela interpreta a entrada.

# Exemplos comuns:
- **SQL Injection:** Quando o input do utilizador é inserido em queries SQL, permitindo ao atacante manipular a base de dados para aceder, modificar ou apagar informação, podendo roubar dados sensíveis como credenciais.
- **Command Injection:** Quando o input do utilizador é passado para comandos do sistema, permitindo a execução de comandos arbitrários no servidor da aplicação, com risco para o sistema.

# Defesas principais contra injection:
- **Lista de permissões (allow list):** O input é comparado a uma lista de valores seguros; se não estiver na lista, é rejeitado.
- **Remoção de caracteres perigosos:** São eliminados caracteres que possam alterar a forma como os dados são processados.
- Em vez de criar listas ou remover manualmente, existem bibliotecas que fazem este trabalho automaticamente para proteger as aplicações.

