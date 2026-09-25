using System.Security.Cryptography;
using System.Text;
using ArvoreMerkle.Core;
using Xunit;

namespace ArvoreMerkle.Tests;

public sealed class ArvoreTest
{
    private static List<byte[]> Itens(int quantos) =>
        Enumerable.Range(0, quantos).Select(i => Encoding.UTF8.GetBytes($"item-{i}")).ToList();

    [Fact]
    public void UmaFolhaSoJaEUmaArvore()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(1));

        Assert.Equal(1, arvore.QuantidadeDeFolhas);
        Assert.Equal(1, arvore.Altura);
        Assert.Equal(arvore.Folhas[0], arvore.Raiz);
    }

    [Fact]
    public void SemFolhaNenhumaNaoHaArvore()
    {
        // Devolver o hash de nada criaria uma raiz que "confere" para qualquer
        // lista vazia — inclusive uma que deveria ter dado erro antes.
        Assert.Throws<ArgumentException>(() => new ArvoreDeMerkle([]));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(3, 3)]
    [InlineData(4, 3)]
    [InlineData(5, 4)]
    [InlineData(8, 4)]
    [InlineData(9, 5)]
    [InlineData(1000, 11)]
    public void AAlturaEOLogaritmoArredondadoParaCima(int folhas, int alturaEsperada)
    {
        Assert.Equal(alturaEsperada, ArvoreDeMerkle.DeItens(Itens(folhas)).Altura);
    }

    [Fact]
    public void MudarUmByteMudaARaiz()
    {
        var itens = Itens(100);
        var antes = ArvoreDeMerkle.DeItens(itens).Raiz;

        itens[42] = Encoding.UTF8.GetBytes("item-42 alterado");

        var depois = ArvoreDeMerkle.DeItens(itens).Raiz;

        Assert.NotEqual(Convert.ToHexString(antes), Convert.ToHexString(depois));
    }

    [Fact]
    public void TrocarDoisItensDeLugarMudaARaiz()
    {
        // A árvore resume uma **lista**, não um conjunto. Se a ordem não
        // importasse, duas listas com os mesmos itens seriam indistinguíveis —
        // e num livro-razão a ordem é tudo.
        var itens = Itens(8);
        var antes = ArvoreDeMerkle.DeItens(itens).Raiz;

        (itens[2], itens[5]) = (itens[5], itens[2]);

        Assert.NotEqual(
            Convert.ToHexString(antes),
            Convert.ToHexString(ArvoreDeMerkle.DeItens(itens).Raiz));
    }

    [Fact]
    public void AMesmaListaDaSempreAMesmaRaiz()
    {
        var itens = Itens(50);

        Assert.Equal(
            Convert.ToHexString(ArvoreDeMerkle.DeItens(itens).Raiz),
            Convert.ToHexString(ArvoreDeMerkle.DeItens(itens).Raiz));
    }

    [Fact]
    public void ONivelZeroSaoAsFolhas()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(7));

        Assert.Equal(7, arvore.Nivel(0).Count);
        Assert.Equal(1, arvore.Nivel(arvore.Altura - 1).Count);
    }

    [Fact]
    public void NivelForaDaFaixaERecusado()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(4));

        Assert.Throws<ArgumentOutOfRangeException>(() => arvore.Nivel(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => arvore.Nivel(arvore.Altura));
    }

    [Fact]
    public void AArvoreNaoGuardaReferenciaParaOsBytesDeFora()
    {
        // Se guardasse, alterar o array depois de montar mudaria a árvore por
        // baixo — e a raiz deixaria de corresponder ao que ela diz resumir.
        var folha = EsquemaBitcoin.Duplo(Encoding.UTF8.GetBytes("a"));
        var arvore = new ArvoreDeMerkle([folha, EsquemaBitcoin.Duplo(Encoding.UTF8.GetBytes("b"))]);
        var raizAntes = Convert.ToHexString(arvore.Raiz);

        Array.Clear(folha);

        Assert.Equal(raizAntes, Convert.ToHexString(arvore.Raiz));
    }

    [Fact]
    public void AlterarARaizDevolvidaNaoAfetaAArvore()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(4));
        var raiz = arvore.Raiz;

        Array.Clear(raiz);

        Assert.NotEqual(Convert.ToHexString(raiz), Convert.ToHexString(arvore.Raiz));
    }
}

public sealed class ProvaTest
{
    private static List<byte[]> Itens(int quantos) =>
        Enumerable.Range(0, quantos).Select(i => Encoding.UTF8.GetBytes($"item-{i}")).ToList();

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(100)]
    [InlineData(1023)]
    public void TodaFolhaTemUmaProvaQueLevaARaiz(int quantas)
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(quantas));

        for (var i = 0; i < quantas; i++)
        {
            Assert.True(arvore.Provar(i).Confere(arvore.Raiz), $"a prova da folha {i} de {quantas} falhou");
        }
    }

    [Fact]
    public void AProvaCresceComOLogaritmoDaLista()
    {
        // É o argumento inteiro da estrutura: a lista cresce mil vezes e a
        // prova cresce dez hashes.
        Assert.Equal(10, ArvoreDeMerkle.DeItens(Itens(1_000)).Provar(500).Tamanho);
        Assert.Equal(20, ArvoreDeMerkle.DeItens(Itens(1_000_000)).Provar(500_000).Tamanho);
    }

    [Fact]
    public void UmaProvaDeOutraArvoreNaoConfere()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(16));
        var outra = ArvoreDeMerkle.DeItens(Itens(16).Select(i => i.Append((byte)1).ToArray()).ToList());

        Assert.False(arvore.Provar(3).Confere(outra.Raiz));
    }

    [Fact]
    public void TrocarOLadoDeUmPassoQuebraAProva()
    {
        // `hash(a‖b)` não é `hash(b‖a)`. Uma prova sem o lado de cada irmão só
        // funcionaria por sorte, e o teste mostra que a sorte não vem.
        var arvore = ArvoreDeMerkle.DeItens(Itens(8));
        var prova = arvore.Provar(3);

        var trocada = prova.Passos
            .Select(p => new PassoDaProva(p.Irmao, p.Lado == Lado.Esquerda ? Lado.Direita : Lado.Esquerda))
            .ToList();

        var forjada = new ArvoreDeMerkle(Itens(8).Select(EsquemaBitcoin.Instancia.Folha).ToList());

        Assert.NotEqual(
            Convert.ToHexString(prova.CalcularRaiz()),
            Convert.ToHexString(Refazer(prova.Folha, trocada)));

        static byte[] Refazer(byte[] folha, IEnumerable<PassoDaProva> passos)
        {
            var atual = folha;

            foreach (var passo in passos)
            {
                atual = passo.Lado == Lado.Esquerda
                    ? EsquemaBitcoin.Instancia.Interno(passo.Irmao, atual)
                    : EsquemaBitcoin.Instancia.Interno(atual, passo.Irmao);
            }

            return atual;
        }
    }

    [Fact]
    public void AlterarUmIrmaoQuebraAProva()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(16));
        var prova = arvore.Provar(5);

        prova.Passos[0].Irmao[0] ^= 0xFF;

        Assert.False(prova.Confere(arvore.Raiz));
    }

    [Fact]
    public void IndiceForaDaFaixaERecusado()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(4));

        Assert.Throws<ArgumentOutOfRangeException>(() => arvore.Provar(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => arvore.Provar(4));
    }

    [Fact]
    public void ComUmaFolhaSoAProvaEVazia()
    {
        var arvore = ArvoreDeMerkle.DeItens(Itens(1));
        var prova = arvore.Provar(0);

        Assert.Empty(prova.Passos);
        Assert.True(prova.Confere(arvore.Raiz));
    }
}

public sealed class EsquemaTest
{
    [Fact]
    public void ORfc6962SeparaFolhaDeNoInterno()
    {
        // Sem o prefixo, nada distingue o hash de uma folha do de um nó
        // interno — e quem controla o conteúdo de uma folha pode fazê-la
        // parecer um nó, fabricando provas para itens que nunca entraram.
        var dado = Encoding.UTF8.GetBytes("qualquer coisa");

        var comoFolha = EsquemaRfc6962.Instancia.Folha(dado);
        var comoInterno = SHA256.HashData(Prefixar(EsquemaRfc6962.PrefixoInterno, dado));

        Assert.NotEqual(Convert.ToHexString(comoFolha), Convert.ToHexString(comoInterno));

        static byte[] Prefixar(byte prefixo, byte[] dado)
        {
            var com = new byte[dado.Length + 1];

            com[0] = prefixo;
            dado.CopyTo(com, 1);

            return com;
        }
    }

    [Fact]
    public void NoBitcoinFolhaENoInternoUsamAMesmaFuncao()
    {
        // O contraste que explica o prefixo do RFC 6962: aqui o hash de uma
        // folha de 64 bytes é indistinguível do hash de um nó interno.
        var esquerda = EsquemaBitcoin.Duplo(Encoding.UTF8.GetBytes("a"));
        var direita = EsquemaBitcoin.Duplo(Encoding.UTF8.GetBytes("b"));

        var comoInterno = EsquemaBitcoin.Instancia.Interno(esquerda, direita);
        var comoFolha = EsquemaBitcoin.Instancia.Folha([.. esquerda, .. direita]);

        Assert.Equal(Convert.ToHexString(comoInterno), Convert.ToHexString(comoFolha));
    }

    [Fact]
    public void OsDoisEsquemasDaoRaizesDiferentesParaAMesmaLista()
    {
        var itens = Enumerable.Range(0, 8).Select(i => Encoding.UTF8.GetBytes($"i{i}")).ToList();

        var comBitcoin = ArvoreDeMerkle.DeItens(itens, EsquemaBitcoin.Instancia).Raiz;
        var comRfc = ArvoreDeMerkle.DeItens(itens, EsquemaRfc6962.Instancia).Raiz;

        Assert.NotEqual(Convert.ToHexString(comBitcoin), Convert.ToHexString(comRfc));
    }

    [Fact]
    public void AProvaUsaOMesmoEsquemaDaArvore()
    {
        var itens = Enumerable.Range(0, 9).Select(i => Encoding.UTF8.GetBytes($"i{i}")).ToList();
        var arvore = ArvoreDeMerkle.DeItens(itens, EsquemaRfc6962.Instancia);

        for (var i = 0; i < itens.Count; i++)
        {
            Assert.True(arvore.Provar(i).Confere(arvore.Raiz));
        }
    }
}
