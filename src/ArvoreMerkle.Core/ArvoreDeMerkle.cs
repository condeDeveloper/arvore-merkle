using System.Security.Cryptography;

namespace ArvoreMerkle.Core;

/// <summary>
/// Uma árvore de Merkle: resume uma lista inteira num hash só.
/// </summary>
/// <remarks>
/// <para>
/// A ideia é simples e as consequências não são. Cada folha é o hash de um
/// item; cada nó interno é o hash da concatenação dos dois filhos; o topo é a
/// <b>raiz</b>. Mudar um byte em qualquer item muda a raiz.
/// </para>
/// <para>
/// O que a torna útil não é resumir — qualquer hash faz isso. É provar
/// <b>pertencimento</b>: para convencer alguém de que um item está numa lista
/// de um milhão, não é preciso mandar a lista. Bastam <c>log₂(1.000.000) ≈ 20</c>
/// hashes, e quem recebe recalcula o caminho até a raiz que já conhece.
/// </para>
/// <para>
/// É por isso que ela está no Bitcoin, no Git, no Certificate Transparency, no
/// IPFS e em todo sistema que precisa dizer "isto aqui é parte daquilo" sem
/// carregar "aquilo".
/// </para>
/// </remarks>
public sealed class ArvoreDeMerkle
{
    private readonly List<byte[]> _folhas;
    private readonly List<List<byte[]>> _niveis;
    private readonly IEsquemaDeHash _esquema;

    /// <summary>Monta a árvore a partir dos itens já hasheados (as folhas).</summary>
    public ArvoreDeMerkle(IEnumerable<byte[]> folhas, IEsquemaDeHash? esquema = null)
    {
        ArgumentNullException.ThrowIfNull(folhas);

        _esquema = esquema ?? EsquemaBitcoin.Instancia;
        _folhas = folhas.Select(f => f.ToArray()).ToList();

        if (_folhas.Count == 0)
        {
            // Uma árvore vazia não tem raiz. Devolver o hash de nada parece
            // inofensivo e cria uma raiz que "confere" para qualquer lista
            // vazia — inclusive uma que deveria ter dado erro antes.
            throw new ArgumentException("uma árvore de Merkle precisa de ao menos uma folha", nameof(folhas));
        }

        _niveis = Construir(_folhas, _esquema);
    }

    /// <summary>A raiz: o resumo da lista inteira.</summary>
    public byte[] Raiz => _niveis[^1][0].ToArray();

    /// <summary>Quantas folhas a árvore tem.</summary>
    public int QuantidadeDeFolhas => _folhas.Count;

    /// <summary>
    /// Quantos níveis a árvore tem, contando as folhas e a raiz.
    /// </summary>
    /// <remarks>
    /// É o tamanho de uma prova de pertencimento: com um milhão de folhas são
    /// 21 níveis, logo 20 hashes de prova.
    /// </remarks>
    public int Altura => _niveis.Count;

    /// <summary>As folhas, na ordem em que entraram.</summary>
    public IReadOnlyList<byte[]> Folhas => _folhas;

    private static List<List<byte[]>> Construir(List<byte[]> folhas, IEsquemaDeHash esquema)
    {
        var niveis = new List<List<byte[]>> { folhas.Select(f => f.ToArray()).ToList() };

        while (niveis[^1].Count > 1)
        {
            var atual = niveis[^1];
            var proximo = new List<byte[]>((atual.Count + 1) / 2);

            for (var i = 0; i < atual.Count; i += 2)
            {
                // Nível com número ímpar de nós: o último é emparelhado
                // consigo mesmo. É a regra do Bitcoin, e é a origem de uma
                // vulnerabilidade famosa — ver `Duplicacao.TemParDuplicado`.
                var direita = i + 1 < atual.Count ? atual[i + 1] : atual[i];

                proximo.Add(esquema.Interno(atual[i], direita));
            }

            niveis.Add(proximo);
        }

        return niveis;
    }

    /// <summary>
    /// A prova de que a folha na posição <paramref name="indice"/> pertence à árvore.
    /// </summary>
    /// <remarks>
    /// A prova é a lista de irmãos no caminho da folha até a raiz, com o lado
    /// de cada um. O lado importa: <c>hash(a‖b)</c> não é <c>hash(b‖a)</c>, e
    /// uma prova sem o lado só funciona por sorte.
    /// </remarks>
    public ProvaDePertencimento Provar(int indice)
    {
        if (indice < 0 || indice >= _folhas.Count)
        {
            throw new ArgumentOutOfRangeException(
                nameof(indice), indice, $"a árvore tem {_folhas.Count} folha(s)");
        }

        var passos = new List<PassoDaProva>();
        var posicao = indice;

        for (var nivel = 0; nivel < _niveis.Count - 1; nivel++)
        {
            var atual = _niveis[nivel];
            var ehDireita = posicao % 2 == 1;
            var irmao = ehDireita ? posicao - 1 : Math.Min(posicao + 1, atual.Count - 1);

            passos.Add(new PassoDaProva(atual[irmao].ToArray(), ehDireita ? Lado.Esquerda : Lado.Direita));
            posicao /= 2;
        }

        return new ProvaDePertencimento(_folhas[indice].ToArray(), indice, passos, _esquema);
    }

    /// <summary>Os nós de um nível, com o nível 0 sendo as folhas.</summary>
    public IReadOnlyList<byte[]> Nivel(int nivel)
    {
        if (nivel < 0 || nivel >= _niveis.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(nivel), nivel, $"a árvore tem {_niveis.Count} nível(is)");
        }

        return _niveis[nivel];
    }

    /// <summary>Monta a árvore hasheando os itens crus com o esquema escolhido.</summary>
    public static ArvoreDeMerkle DeItens(IEnumerable<byte[]> itens, IEsquemaDeHash? esquema = null)
    {
        ArgumentNullException.ThrowIfNull(itens);

        var usado = esquema ?? EsquemaBitcoin.Instancia;

        return new ArvoreDeMerkle(itens.Select(usado.Folha), usado);
    }
}

/// <summary>De que lado o irmão fica na concatenação.</summary>
public enum Lado
{
    /// <summary>O irmão entra antes: <c>hash(irmao ‖ atual)</c>.</summary>
    Esquerda,

    /// <summary>O irmão entra depois: <c>hash(atual ‖ irmao)</c>.</summary>
    Direita,
}

/// <summary>Um degrau da prova: o hash do irmão e de que lado ele entra.</summary>
public readonly record struct PassoDaProva(byte[] Irmao, Lado Lado);
