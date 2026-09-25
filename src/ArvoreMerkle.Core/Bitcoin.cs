using System.Globalization;

namespace ArvoreMerkle.Core;

/// <summary>
/// A raiz de Merkle de um bloco de Bitcoin, com as duas pegadinhas que ela tem.
/// </summary>
public static class Bitcoin
{
    /// <summary>
    /// Calcula a raiz de Merkle a partir dos txid como um explorador os exibe.
    /// </summary>
    /// <remarks>
    /// <b>A inversão de bytes.</b> O Bitcoin calcula hashes em ordem natural e
    /// os <b>exibe</b> invertidos. Um txid copiado de um explorador precisa ser
    /// invertido antes de entrar na conta, e a raiz calculada precisa ser
    /// invertida de volta antes de comparar com a publicada. É a primeira coisa
    /// que dá errado para quem tenta reproduzir uma raiz de bloco.
    /// </remarks>
    public static string RaizDeBloco(IReadOnlyList<string> txidsComoExibidos)
    {
        ArgumentNullException.ThrowIfNull(txidsComoExibidos);

        if (txidsComoExibidos.Count == 0)
        {
            throw new ArgumentException("um bloco tem ao menos a transação geradora", nameof(txidsComoExibidos));
        }

        var folhas = txidsComoExibidos.Select(DeHexInvertido).ToList();
        var arvore = new ArvoreDeMerkle(folhas, EsquemaBitcoin.Instancia);

        return ParaHexInvertido(arvore.Raiz);
    }

    /// <summary>Lê um hash em hexadecimal e inverte os bytes.</summary>
    public static byte[] DeHexInvertido(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);

        if (hex.Length % 2 != 0)
        {
            throw new FormatException($"um hash em hexadecimal tem número par de dígitos: \"{hex}\"");
        }

        var bytes = new byte[hex.Length / 2];

        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[bytes.Length - 1 - i] = byte.Parse(
                hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return bytes;
    }

    /// <summary>Escreve um hash em hexadecimal com os bytes invertidos.</summary>
    public static string ParaHexInvertido(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);

        // `ToHexStringLower` só existe no .NET 9; este projeto é net8.0.
        return Convert.ToHexString(hash.Reverse().ToArray()).ToLowerInvariant();
    }
}

/// <summary>
/// A vulnerabilidade que a regra de duplicação abriu no Bitcoin.
/// </summary>
/// <remarks>
/// <para>
/// Quando um nível tem número ímpar de nós, o último é emparelhado consigo
/// mesmo. Daí sai uma consequência que passou despercebida por três anos: uma
/// lista de <c>n</c> transações e uma lista de <c>n + k</c> em que as últimas
/// <c>k</c> repetem as anteriores <b>podem produzir a mesma raiz</b>.
/// </para>
/// <para>
/// Em 2012 isso virou a <b>CVE-2012-2459</b>. Um atacante pegava um bloco
/// válido, duplicava transações de forma a manter a raiz, e transmitia o bloco
/// alterado. Os nós o rejeitavam por ter transação repetida — e marcavam o
/// <b>hash do bloco</b> como inválido para sempre. Como o hash do bloco depende
/// só do cabeçalho, e o cabeçalho é idêntico, o bloco <b>legítimo</b> passava a
/// ser recusado. Uma negação de serviço que dividia a rede sem precisar de
/// poder de mineração nenhum.
/// </para>
/// <para>
/// A correção foi verificar a duplicação antes de aceitar. É o que
/// <see cref="TemParDuplicado"/> faz — e é por isso que ela existe aqui em vez
/// de um comentário dizendo "cuidado".
/// </para>
/// </remarks>
public static class Duplicacao
{
    /// <summary>
    /// Se a lista tem um par de folhas vizinhas idênticas em alguma posição par.
    /// </summary>
    /// <remarks>
    /// É exatamente a forma que permite forjar uma raiz igual: duplicar o
    /// último elemento de um nível. Qualquer lista que contenha esse padrão é
    /// ambígua e não deve ser aceita sem conferência.
    /// </remarks>
    public static bool TemParDuplicado(IReadOnlyList<byte[]> folhas)
    {
        ArgumentNullException.ThrowIfNull(folhas);

        for (var i = 0; i + 1 < folhas.Count; i += 2)
        {
            if (folhas[i].AsSpan().SequenceEqual(folhas[i + 1]))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Monta a lista alterada que produz a mesma raiz de <paramref name="folhas"/>.
    /// </summary>
    /// <remarks>
    /// Só existe para o teste poder <b>demonstrar</b> o ataque em vez de
    /// descrevê-lo. Só funciona quando a contagem é ímpar, que é o caso em que
    /// a duplicação acontece.
    /// </remarks>
    public static IReadOnlyList<byte[]>? Forjar(IReadOnlyList<byte[]> folhas)
    {
        ArgumentNullException.ThrowIfNull(folhas);

        if (folhas.Count < 3 || folhas.Count % 2 == 0)
        {
            return null;
        }

        // A árvore já duplica a última folha internamente. Duplicá-la de
        // verdade na entrada produz o mesmo nível seguinte — e, portanto, a
        // mesma raiz — com uma lista diferente.
        var forjada = folhas.Select(f => f.ToArray()).ToList();

        forjada.Add(folhas[^1].ToArray());

        return forjada;
    }
}
