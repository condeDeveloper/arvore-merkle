# arvore-merkle

Árvore de Merkle escrita do zero em C# e .NET 8, com provas de pertencimento —
e a prova de que está certa são **raízes de blocos reais do Bitcoin**.

```
$ dotnet src/ArvoreMerkle.Cli/bin/Release/net8.0/ArvoreMerkle.Cli.dll bloco blocos/bloco-130000.txt
transações: 9
calculada:  b98fb57041d995378f29f9f0ce06e14fb2265803c312f0fadb1947ebd35ec644
publicada:  b98fb57041d995378f29f9f0ce06e14fb2265803c312f0fadb1947ebd35ec644
confere.
```

## O que a estrutura compra

Cada folha é o hash de um item; cada nó interno é o hash dos dois filhos; o
topo é a raiz. Mudar um byte em qualquer item muda a raiz.

Resumir, porém, qualquer hash faz. O que a árvore compra é provar
**pertencimento**: para convencer alguém de que um item está numa lista de um
milhão, não é preciso mandar a lista.

```
$ dotnet …/ArvoreMerkle.Cli.dll demonstrar

       itens     prova     prova/lista   tempo p/ montar
----------------------------------------------------------
          10         4       40,0000%             11 ms
       1.000        10        1,0000%              2 ms
     100.000        17        0,0170%            251 ms
   1.000.000        20        0,0020%           2530 ms

Com um milhão de itens, a prova são 20 hashes — 640 bytes.
```

A lista cresce mil vezes e a prova cresce dez hashes. É por isso que uma
carteira de Bitcoin que não guarda a cadeia inteira consegue funcionar: ela tem
só os cabeçalhos de 80 bytes e pede a prova ao servidor, que não consegue
mentir porque a raiz já está no cabeçalho.

## O oráculo: quatro blocos reais

A raiz de Merkle de um bloco está publicada no cabeçalho dele e é conferida por
dezenas de milhares de nós há mais de quinze anos. Se o código daqui chega ao
mesmo valor a partir dos txid, não há discussão possível.

| bloco | transações | por que ele está aqui |
|---|---|---|
| 91722 | 1 | a raiz **é** o txid; nada a juntar |
| 170 | 2 | o caso mínimo de verdade |
| 100000 | 4 | potência de 2, a árvore perfeita |
| **130000** | **9** | ímpar — duplicação em **três** níveis |

O de nove é o que importa: 9 → 5 → 3 → 2 → 1, e em três desses níveis a
contagem é ímpar. Um bloco de 4 transações não denunciaria um erro na regra de
duplicação; este denuncia.

Os arquivos estão em `tests/ArvoreMerkle.Tests/blocos/`, capturados da API
pública do Blockstream em 2026-09-25, com a URL de origem escrita no cabeçalho
de cada um. São 4 KB de texto — nenhum dado de cadeia entra no repositório.

## As duas pegadinhas do Bitcoin

**1. Os bytes são exibidos invertidos.** O Bitcoin calcula os hashes em ordem
natural e os mostra ao contrário. Um txid copiado de um explorador precisa ser
invertido antes de entrar na conta, e a raiz calculada precisa ser invertida de
volta antes de comparar. Um teste calcula sem inverter de propósito: o
resultado é um hash perfeitamente plausível e completamente errado.

**2. O hash é duplo.** SHA-256 aplicado duas vezes. É herança de 2008 —
justificada na época como proteção contra extensão de comprimento, que do jeito
que o Bitcoin usa nem se aplicava. Ficou.

## A CVE-2012-2459, demonstrada

Quando um nível tem número ímpar de nós, o último é emparelhado consigo mesmo.
Daí sai uma consequência que passou três anos despercebida: **duas listas
diferentes podem produzir a mesma raiz.**

```csharp
var original = Folhas(5);
var forjada  = Duplicacao.Forjar(original);   // 6 folhas, a última repetida

new ArvoreDeMerkle(original).Raiz == new ArvoreDeMerkle(forjada).Raiz   // true
```

Em 2012 isso virou ataque. Pegava-se um bloco válido, duplicavam-se transações
mantendo a raiz, e transmitia-se o bloco alterado. Os nós o rejeitavam por ter
transação repetida — e marcavam o **hash do bloco** como inválido para sempre.
Como o hash do bloco depende só do cabeçalho, e o cabeçalho é idêntico, o bloco
**legítimo** passava a ser recusado. Uma negação de serviço que dividia a rede
sem custar poder de mineração nenhum.

A defesa está em `Duplicacao.TemParDuplicado`, e os testes mostram o ataque
funcionando para 3, 5, 7 e 9 folhas e a defesa pegando todos — além de conferir
que ela **não** acusa uma lista legítima que por acaso tenha itens repetidos em
posições quaisquer.

## O byte que separa o RFC 6962 do Bitcoin

No Certificate Transparency a folha é `SHA-256(0x00 ‖ dado)` e o nó interno é
`SHA-256(0x01 ‖ esquerda ‖ direita)`.

Sem esse prefixo, nada distingue o hash de uma folha do hash de um nó interno —
e quem controla o conteúdo de uma folha pode fazê-la parecer um nó, fabricando
provas para itens que nunca entraram na árvore. É o ataque de **segunda
pré-imagem**, e o preço da defesa é um byte.

Um teste mostra o contraste de forma direta: no esquema do Bitcoin, o hash de
uma folha de 64 bytes é **idêntico** ao hash do nó interno formado por essas
duas metades.

## Detalhes que decidem se está certo

- **A ordem importa.** A árvore resume uma *lista*, não um conjunto. Trocar
  dois itens de lugar muda a raiz — num livro-razão, a ordem é tudo.
- **O lado do irmão faz parte da prova.** `hash(a‖b)` não é `hash(b‖a)`. Uma
  prova sem o lado só funcionaria por sorte.
- **Árvore vazia é erro, não hash de nada.** Devolver o hash do vazio cria uma
  raiz que "confere" para qualquer lista vazia, inclusive uma que deveria ter
  falhado antes.
- **Os bytes são copiados na entrada e na saída.** Sem isso, alterar o array
  depois de montar mudaria a árvore por baixo, e a raiz deixaria de
  corresponder ao que ela diz resumir.

## Rodando

```bash
dotnet test -c Release

dotnet build -c Release
dotnet src/ArvoreMerkle.Cli/bin/Release/net8.0/ArvoreMerkle.Cli.dll raiz arquivo.txt
dotnet src/ArvoreMerkle.Cli/bin/Release/net8.0/ArvoreMerkle.Cli.dll prova arquivo.txt 3
dotnet src/ArvoreMerkle.Cli/bin/Release/net8.0/ArvoreMerkle.Cli.dll bloco blocos/bloco-100000.txt
dotnet src/ArvoreMerkle.Cli/bin/Release/net8.0/ArvoreMerkle.Cli.dll demonstrar
```

Como biblioteca:

```csharp
var arvore = ArvoreDeMerkle.DeItens(itens);          // esquema do Bitcoin
var prova  = arvore.Provar(indice);

prova.Tamanho;                 // ⌈log₂(n)⌉ hashes
prova.Confere(arvore.Raiz);    // true

// Certificate Transparency, com o prefixo de domínio:
ArvoreDeMerkle.DeItens(itens, EsquemaRfc6962.Instancia);

// A raiz de um bloco, a partir dos txid como um explorador os exibe:
Bitcoin.RaizDeBloco(txids);
```

53 testes.

## Estrutura

```
src/ArvoreMerkle.Core/ArvoreDeMerkle.cs        a árvore e as provas
src/ArvoreMerkle.Core/EsquemaDeHash.cs         Bitcoin e RFC 6962
src/ArvoreMerkle.Core/ProvaDePertencimento.cs  refazer o caminho até a raiz
src/ArvoreMerkle.Core/Bitcoin.cs               inversão de bytes e a CVE-2012-2459
tests/ArvoreMerkle.Tests/blocos/               os quatro blocos reais
```

## Limites conhecidos

- **A árvore é imutável.** Acrescentar um item refaz tudo. As variantes
  incrementais (a árvore *append-only* do Certificate Transparency, por
  exemplo) guardam os nós de fronteira e acrescentam em O(log n); aqui não.
- **Sem prova de consistência.** O RFC 6962 define também a prova de que uma
  árvore é extensão de outra — é o que torna um log auditável. Só a prova de
  pertencimento está implementada.
- **Tudo em memória.** Um milhão de folhas de 32 bytes são 32 MB só de folhas,
  mais os níveis. Para listas grandes de verdade, os nós vão para disco.
- **Sem árvore esparsa.** As Merkle Patricia Tries, que o Ethereum usa para
  provar *ausência* de uma chave, são outra estrutura.
- **Sem paralelismo.** Cada nível é independente e daria para calcular em
  paralelo; o milhão de itens leva 2,5 s num núcleo só.

## Licença

MIT.
