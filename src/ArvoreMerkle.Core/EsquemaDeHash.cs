using System.Security.Cryptography;

namespace ArvoreMerkle.Core;

/// <summary>
/// Como a árvore transforma dados em hash.
/// </summary>
/// <remarks>
/// Existe como interface porque <b>cada sistema escolhe diferente, e a escolha
/// muda a raiz</b>. O Bitcoin usa SHA-256 duas vezes; o Certificate
/// Transparency prefixa um byte para separar folha de nó interno; o Git usa
/// SHA-1 com um cabeçalho de tipo e tamanho. Uma árvore que fixa o esquema não
/// consegue conferir a raiz de nenhum deles.
/// </remarks>
public interface IEsquemaDeHash
{
    /// <summary>O hash de uma folha, a partir do dado cru.</summary>
    byte[] Folha(byte[] dado);

    /// <summary>O hash de um nó interno, a partir dos dois filhos.</summary>
    byte[] Interno(byte[] esquerda, byte[] direita);
}

/// <summary>
/// O esquema do Bitcoin: SHA-256 aplicado duas vezes.
/// </summary>
/// <remarks>
/// <para>
/// O hash duplo é herança de 2008. A justificativa da época era proteger
/// contra ataques de extensão de comprimento, que afetam a construção
/// Merkle-Damgård do SHA-2 — embora, do jeito que o Bitcoin usa, o ataque não
/// se aplicasse de todo modo. Ficou.
/// </para>
/// <para>
/// A pegadinha prática é outra: o Bitcoin <b>exibe</b> os hashes com os bytes
/// invertidos em relação a como os calcula. Um txid copiado de um explorador
/// de blocos precisa ser invertido antes de entrar na conta, e a raiz
/// calculada precisa ser invertida de volta antes de comparar. Quem esquece
/// disso obtém uma raiz que não bate com nada e passa a tarde procurando erro
/// no algoritmo.
/// </para>
/// </remarks>
public sealed class EsquemaBitcoin : IEsquemaDeHash
{
    /// <summary>A única instância necessária: o esquema não tem estado.</summary>
    public static readonly EsquemaBitcoin Instancia = new();

    /// <inheritdoc />
    public byte[] Folha(byte[] dado)
    {
        ArgumentNullException.ThrowIfNull(dado);

        return Duplo(dado);
    }

    /// <inheritdoc />
    public byte[] Interno(byte[] esquerda, byte[] direita)
    {
        ArgumentNullException.ThrowIfNull(esquerda);
        ArgumentNullException.ThrowIfNull(direita);

        var juntos = new byte[esquerda.Length + direita.Length];

        esquerda.CopyTo(juntos, 0);
        direita.CopyTo(juntos, esquerda.Length);

        return Duplo(juntos);
    }

    /// <summary>SHA-256 duas vezes.</summary>
    public static byte[] Duplo(byte[] dado) => SHA256.HashData(SHA256.HashData(dado));
}

/// <summary>
/// O esquema do RFC 6962 (Certificate Transparency).
/// </summary>
/// <remarks>
/// <para>
/// A diferença para o do Bitcoin é um byte, e ele resolve um problema real: a
/// folha é <c>SHA-256(0x00 ‖ dado)</c> e o nó interno é
/// <c>SHA-256(0x01 ‖ esquerda ‖ direita)</c>.
/// </para>
/// <para>
/// Sem esse prefixo, nada distingue o hash de uma folha do hash de um nó
/// interno — e quem controla o conteúdo de uma folha pode fazê-la parecer um
/// nó interno, fabricando provas para itens que nunca entraram na árvore. É o
/// <b>ataque de segunda pré-imagem</b>, e o preço da defesa é um byte.
/// </para>
/// </remarks>
public sealed class EsquemaRfc6962 : IEsquemaDeHash
{
    /// <summary>A única instância necessária.</summary>
    public static readonly EsquemaRfc6962 Instancia = new();

    /// <summary>O prefixo que marca uma folha.</summary>
    public const byte PrefixoDeFolha = 0x00;

    /// <summary>O prefixo que marca um nó interno.</summary>
    public const byte PrefixoInterno = 0x01;

    /// <inheritdoc />
    public byte[] Folha(byte[] dado)
    {
        ArgumentNullException.ThrowIfNull(dado);

        var com = new byte[dado.Length + 1];

        com[0] = PrefixoDeFolha;
        dado.CopyTo(com, 1);

        return SHA256.HashData(com);
    }

    /// <inheritdoc />
    public byte[] Interno(byte[] esquerda, byte[] direita)
    {
        ArgumentNullException.ThrowIfNull(esquerda);
        ArgumentNullException.ThrowIfNull(direita);

        var com = new byte[1 + esquerda.Length + direita.Length];

        com[0] = PrefixoInterno;
        esquerda.CopyTo(com, 1);
        direita.CopyTo(com, 1 + esquerda.Length);

        return SHA256.HashData(com);
    }
}
