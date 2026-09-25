namespace ArvoreMerkle.Core;

/// <summary>
/// A prova de que um item está na árvore, sem precisar da árvore.
/// </summary>
/// <remarks>
/// <para>
/// É o que torna a estrutura útil. Para convencer alguém de que uma transação
/// está num bloco de dez mil, não se manda o bloco: mandam-se 14 hashes. Quem
/// recebe refaz o caminho até a raiz — que já conhece por outro meio — e
/// compara.
/// </para>
/// <para>
/// Uma carteira de Bitcoin que não guarda a cadeia inteira funciona assim: ela
/// tem só os cabeçalhos (80 bytes cada) e pede a prova ao servidor. O servidor
/// não consegue mentir, porque a raiz está no cabeçalho que a carteira já tem.
/// </para>
/// </remarks>
public sealed class ProvaDePertencimento
{
    private readonly IEsquemaDeHash _esquema;

    internal ProvaDePertencimento(byte[] folha, int indice, IReadOnlyList<PassoDaProva> passos, IEsquemaDeHash esquema)
    {
        Folha = folha;
        Indice = indice;
        Passos = passos;
        _esquema = esquema;
    }

    /// <summary>O hash da folha que a prova defende.</summary>
    public byte[] Folha { get; }

    /// <summary>A posição da folha na árvore.</summary>
    public int Indice { get; }

    /// <summary>Os irmãos no caminho até a raiz.</summary>
    public IReadOnlyList<PassoDaProva> Passos { get; }

    /// <summary>Quantos hashes a prova carrega.</summary>
    public int Tamanho => Passos.Count;

    /// <summary>Refaz o caminho e devolve a raiz a que a prova leva.</summary>
    public byte[] CalcularRaiz()
    {
        var atual = Folha;

        foreach (var passo in Passos)
        {
            atual = passo.Lado == Lado.Esquerda
                ? _esquema.Interno(passo.Irmao, atual)
                : _esquema.Interno(atual, passo.Irmao);
        }

        return atual;
    }

    /// <summary>Se a prova leva à raiz esperada.</summary>
    public bool Confere(byte[] raizEsperada)
    {
        ArgumentNullException.ThrowIfNull(raizEsperada);

        // Comparação em tempo fixo: a raiz é pública, mas comparar hash com
        // saída antecipada é um hábito que, no dia em que o dado for secreto,
        // vira vazamento. Custa nada manter.
        return CryptographicOperations.FixedTimeEquals(CalcularRaiz(), raizEsperada);
    }
}
