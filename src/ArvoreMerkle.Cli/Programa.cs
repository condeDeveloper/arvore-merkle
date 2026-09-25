using System.Diagnostics;
using System.Globalization;
using System.Text;
using ArvoreMerkle.Core;

namespace ArvoreMerkle.Cli;

/// <summary>
/// A linha de comando.
/// </summary>
/// <remarks>
/// <code>
///   dotnet run --project src/ArvoreMerkle.Cli -- raiz arquivo.txt
///   dotnet run --project src/ArvoreMerkle.Cli -- prova arquivo.txt 3
///   dotnet run --project src/ArvoreMerkle.Cli -- bloco tests/.../blocos/bloco-100000.txt
///   dotnet run --project src/ArvoreMerkle.Cli -- demonstrar
/// </code>
/// </remarks>
public static class Programa
{
    public static int Main(string[] argumentos)
    {
        if (argumentos.Length == 0)
        {
            Uso();

            return 1;
        }

        try
        {
            return argumentos[0] switch
            {
                "raiz" => Raiz(argumentos),
                "prova" => Prova(argumentos),
                "bloco" => Bloco(argumentos),
                "demonstrar" => Demonstrar(),
                _ => Desconhecido(argumentos[0]),
            };
        }
        catch (Exception erro) when (erro is ArgumentException or FormatException or IOException)
        {
            Console.Error.WriteLine(erro.Message);

            return 2;
        }
    }

    private static void Uso() => Console.WriteLine(
        """
        arvore-merkle — árvore de Merkle, provas de pertencimento e a raiz de um bloco

          raiz <arquivo>            a raiz das linhas do arquivo
          prova <arquivo> <linha>   a prova de pertencimento de uma linha
          bloco <arquivo>           confere a raiz de um bloco de Bitcoin
          demonstrar                o tamanho da prova conforme a lista cresce
        """);

    private static int Desconhecido(string comando)
    {
        Console.Error.WriteLine($"comando desconhecido: {comando}");
        Uso();

        return 1;
    }

    private static List<byte[]> LerLinhas(string caminho) =>
        File.ReadAllLines(caminho)
            .Where(l => l.Length > 0)
            .Select(l => Encoding.UTF8.GetBytes(l))
            .ToList();

    private static int Raiz(string[] argumentos)
    {
        if (argumentos.Length < 2)
        {
            Console.Error.WriteLine("uso: raiz <arquivo>");

            return 1;
        }

        var itens = LerLinhas(argumentos[1]);
        var arvore = ArvoreDeMerkle.DeItens(itens);

        Console.WriteLine($"folhas:  {arvore.QuantidadeDeFolhas}");
        Console.WriteLine($"altura:  {arvore.Altura}");
        Console.WriteLine($"raiz:    {Convert.ToHexString(arvore.Raiz).ToLowerInvariant()}");

        return 0;
    }

    private static int Prova(string[] argumentos)
    {
        if (argumentos.Length < 3)
        {
            Console.Error.WriteLine("uso: prova <arquivo> <linha>");

            return 1;
        }

        var itens = LerLinhas(argumentos[1]);
        var arvore = ArvoreDeMerkle.DeItens(itens);
        var indice = int.Parse(argumentos[2], CultureInfo.InvariantCulture);
        var prova = arvore.Provar(indice);

        Console.WriteLine($"item:    linha {indice}");
        Console.WriteLine($"prova:   {prova.Tamanho} hash(es), para uma lista de {itens.Count}");

        foreach (var passo in prova.Passos)
        {
            var lado = passo.Lado == Lado.Esquerda ? "irmão à esquerda" : "irmão à direita";

            Console.WriteLine($"  {lado}: {Convert.ToHexString(passo.Irmao).ToLowerInvariant()[..16]}…");
        }

        Console.WriteLine($"confere: {prova.Confere(arvore.Raiz)}");

        return prova.Confere(arvore.Raiz) ? 0 : 1;
    }

    private static int Bloco(string[] argumentos)
    {
        if (argumentos.Length < 2)
        {
            Console.Error.WriteLine("uso: bloco <arquivo>");

            return 1;
        }

        string? esperada = null;
        var txids = new List<string>();

        foreach (var linha in File.ReadAllLines(argumentos[1]))
        {
            if (linha.StartsWith('#') || linha.Length == 0)
            {
                continue;
            }

            if (linha.StartsWith("raiz=", StringComparison.Ordinal))
            {
                esperada = linha["raiz=".Length..].Trim();
            }
            else
            {
                txids.Add(linha.Trim());
            }
        }

        var calculada = Core.Bitcoin.RaizDeBloco(txids);

        Console.WriteLine($"transações: {txids.Count}");
        Console.WriteLine($"calculada:  {calculada}");
        Console.WriteLine($"publicada:  {esperada}");
        Console.WriteLine(calculada == esperada ? "confere." : "NÃO CONFERE.");

        return calculada == esperada ? 0 : 1;
    }

    private static int Demonstrar()
    {
        Console.WriteLine("O que a árvore economiza: provar pertencimento sem mandar a lista.\n");
        Console.WriteLine($"{"itens",12}  {"prova",8}  {"prova/lista",14}  {"tempo p/ montar",16}");
        Console.WriteLine(new string('-', 58));

        foreach (var quantos in new[] { 10, 1_000, 100_000, 1_000_000 })
        {
            var itens = new List<byte[]>(quantos);

            for (var i = 0; i < quantos; i++)
            {
                itens.Add(Encoding.UTF8.GetBytes($"item-{i}"));
            }

            var relogio = Stopwatch.StartNew();
            var arvore = ArvoreDeMerkle.DeItens(itens);

            relogio.Stop();

            var prova = arvore.Provar(quantos / 2);
            var fracao = (double)prova.Tamanho / quantos;

            Console.WriteLine(
                $"{quantos,12:N0}  {prova.Tamanho,8}  {fracao,13:P4}  {relogio.ElapsedMilliseconds,13} ms");
        }

        Console.WriteLine("\nCom um milhão de itens, a prova são 20 hashes — 640 bytes.");

        return 0;
    }
}
