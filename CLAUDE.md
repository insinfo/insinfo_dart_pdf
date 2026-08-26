# Instruções do repositório

## Commits

**Não adicione trailer de atribuição de IA/agente.** Nenhum
`Co-Authored-By: Claude ...`, nenhum "Generated with", nenhuma linha que credite
um agente. A mensagem termina no último parágrafo de conteúdo.

O mesmo vale para corpos de pull request: sem rodapé "🤖 Generated with".

### Escrevendo a mensagem

O shell POSIX deste repositório é o Git Bash (Windows). Here-strings do
PowerShell (`@'...'@`) são erro de sintaxe nele e já produziram um commit cujo
assunto virou `@`. Para mensagens de várias linhas, escreva o texto em um
arquivo temporário e use:

```bash
git commit -F <arquivo>
```

Um heredoc do Bash (`<<'EOF'`) também funciona, mas o arquivo é mais previsível
com mensagens longas.
