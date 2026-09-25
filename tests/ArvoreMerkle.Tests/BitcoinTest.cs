using System.Text;
using ArvoreMerkle.Core;
using Xunit;

namespace ArvoreMerkle.Tests;

/// <summary>
/// O oráculo: blocos reais da cadeia principal do Bitcoin.
/// </summary>
/// <remarks>
/// <para>
/// A raiz de Merkle de um bloco é publicada no cabeçalho dele e conferida por
/// dezenas de milhares de nós há mais de quinze anos. Se a implementação daqui
/// chega ao mesmo valor a partir dos txid, ela está certa — e não há discussão
/// possível sobre isso.
/// </para>
/// <para>
/// Os blocos estão em <c>blocos/*.txt</c>, capturados da API pública do
/// Blockstream em 2026-09-25, com a origem escrita no cabeçalho de cada
/// arquivo. São 4 KB de texto; nenhum dado de cadeia entra no repositório.
/// </para>
/// </remarks>
public sealed class BitcoinTest
{
    private static (string Raiz, List<string> Txids) LerBloco(string nome)
    {
        var caminho = Path.Combine(AppContext.BaseDirectory, "blocos", nome);
        string? raiz = null;
        var txids = new List<string>();

        foreach (var linha in File.ReadAllLines(caminho))
        {
            if (linha.Length == 0 || linha.StartsWith('#'))
            {
                continue;
            }

            if (linha.StartsWith("raiz=", StringComparison.Ordinal))
            {
                raiz = linha["raiz=".Length..].Trim();
            }
            else
            {
                txids.Add(linha.Trim());
            }
        }

        Assert.NotNull(raiz);

        return (raiz!, txids);
    }

    [Theory]
    [InlineData("bloco-91722.txt", 1)]
    [InlineData("bloco-170.txt", 2)]
    [InlineData("bloco-100000.txt", 4)]
    [InlineData("bloco-130000.txt", 9)]
    public void ReproduzARaizPublicadaNoBloco(string arquivo, int quantasTransacoes)
    {
        var (raizPublicada, txids) = LerBloco(arquivo);

        Assert.Equal(quantasTransacoes, txids.Count);
        Assert.Equal(raizPublicada, Bitcoin.RaizDeBloco(txids));
    }

    [Fact]
    public void OBlocoDeNoveTransacoesExercitaADuplicacaoEmTresNiveis()
    {
        // 9 → 5 → 3 → 2 → 1. Em três desses níveis a contagem é ímpar e o
        // último nó é emparelhado consigo mesmo. Se a regra de duplicação
        // estivesse errada, este bloco denunciaria; um bloco de 4 transações,
        // não.
        var (raiz, txids) = LerBloco("bloco-130000.txt");
        var arvore = new ArvoreDeMerkle(txids.Select(Bitcoin.DeHexInvertido).ToList());

        Assert.Equal(9, arvore.Nivel(0).Count);
        Assert.Equal(5, arvore.Nivel(1).Count);
        Assert.Equal(3, arvore.Nivel(2).Count);
        Assert.Equal(2, arvore.Nivel(3).Count);
        Assert.Equal(1, arvore.Nivel(4).Count);
        Assert.Equal(raiz, Bitcoin.ParaHexInvertido(arvore.Raiz));
    }

    [Fact]
    public void ComUmaTransacaoSoARaizEOProprioTxid()
    {
        // Não há nada para juntar, então a raiz é a folha. Vale a pena testar
        // porque é o caso em que um laço mal escrito hasheia uma vez a mais.
        var (raiz, txids) = LerBloco("bloco-91722.txt");

        Assert.Single(txids);
        Assert.Equal(txids[0], raiz);
        Assert.Equal(raiz, Bitcoin.RaizDeBloco(txids));
    }

    [Fact]
    public void AInversaoDeBytesEIdaEVolta()
    {
        const string hex = "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87";

        Assert.Equal(hex, Bitcoin.ParaHexInvertido(Bitcoin.DeHexInvertido(hex)));
    }

    [Fact]
    public void SemInverterOsBytesARaizNaoBate()
    {
        // A prova de que a inversão não é enfeite: calcular sem ela dá um valor
        // perfeitamente plausível e completamente errado.
        var (raizPublicada, txids) = LerBloco("bloco-100000.txt");

        var semInverter = new ArvoreDeMerkle(
            txids.Select(t => Convert.FromHexString(t)).ToList());

        var raizErrada = Convert.ToHexString(semInverter.Raiz).ToLowerInvariant();

        Assert.NotEqual(raizPublicada, raizErrada);
        Assert.Equal(raizPublicada, Bitcoin.RaizDeBloco(txids));
    }

    [Fact]
    public void HexComNumeroImparDeDigitosERecusado()
    {
        Assert.Throws<FormatException>(() => Bitcoin.DeHexInvertido("abc"));
    }

    [Fact]
    public void BlocoSemTransacaoNenhumaERecusado()
    {
        Assert.Throws<ArgumentException>(() => Bitcoin.RaizDeBloco([]));
    }
}

/// <summary>
/// A CVE-2012-2459, demonstrada em vez de descrita.
/// </summary>
public sealed class DuplicacaoTest
{
    private static List<byte[]> Folhas(int quantas) =>
        Enumerable.Range(0, quantas)
            .Select(i => EsquemaBitcoin.Duplo(Encoding.UTF8.GetBytes($"tx-{i}")))
            .ToList();

    [Fact]
    public void DuasListasDiferentesPodemTerAMesmaRaiz()
    {
        // O coração da vulnerabilidade: a árvore duplica a última folha quando
        // a contagem é ímpar, então duplicá-la de verdade na entrada não muda
        // nada — e produz duas listas distintas com a mesma raiz.
        var original = Folhas(5);
        var forjada = Duplicacao.Forjar(original);

        Assert.NotNull(forjada);
        Assert.Equal(6, forjada!.Count);
        Assert.NotEqual(original.Count, forjada.Count);

        var raizOriginal = new ArvoreDeMerkle(original).Raiz;
        var raizForjada = new ArvoreDeMerkle(forjada).Raiz;

        Assert.Equal(Convert.ToHexString(raizOriginal), Convert.ToHexString(raizForjada));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(9)]
    public void OAtaqueFuncionaParaQualquerContagemImpar(int quantas)
    {
        var original = Folhas(quantas);
        var forjada = Duplicacao.Forjar(original)!;

        Assert.Equal(
            Convert.ToHexString(new ArvoreDeMerkle(original).Raiz),
            Convert.ToHexString(new ArvoreDeMerkle(forjada).Raiz));
    }

    [Fact]
    public void ComContagemParNaoHaOQueForjarAssim()
    {
        Assert.Null(Duplicacao.Forjar(Folhas(4)));
        Assert.Null(Duplicacao.Forjar(Folhas(2)));
    }

    [Fact]
    public void ADefesaEnxergaAListaForjada()
    {
        var original = Folhas(5);
        var forjada = Duplicacao.Forjar(original)!;

        Assert.False(Duplicacao.TemParDuplicado(original));
        Assert.True(Duplicacao.TemParDuplicado(forjada));
    }

    [Fact]
    public void ADefesaNaoAcusaListaLegitimaComRepetidosEmPosicaoQualquer()
    {
        // Repetido existe em bloco legítimo; o que denuncia o ataque é o par
        // vizinho em posição par, que é a forma exata que a duplicação cria.
        var folhas = Folhas(6);

        folhas[1] = folhas[4];

        Assert.False(Duplicacao.TemParDuplicado(folhas));
    }

    [Fact]
    public void OBlocoRealDeNoveTransacoesNaoTemParDuplicado()
    {
        var caminho = Path.Combine(AppContext.BaseDirectory, "blocos", "bloco-130000.txt");

        var txids = File.ReadAllLines(caminho)
            .Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith("raiz=", StringComparison.Ordinal))
            .Select(l => Bitcoin.DeHexInvertido(l.Trim()))
            .ToList();

        Assert.False(Duplicacao.TemParDuplicado(txids));
    }
}
