
namespace PcapConverter
{
    internal class Program
    {
        /// <summary>
        /// This program calculates time deltas from .csv files containing info from .pcap files
        /// The .csv files are created using Tshark
        /// </summary>
        /// <param name="_"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        static async Task Main(string[] args)
        {
            string? inputPath;
            string? outputPath;
            string? versionInput;
            string? modeInput;
            string? networkInput;
            Version version;
            HandshakeMode handshakeMode;
            NetworkMode networkMode;

            // Check whether command line arguments have been supplied
            switch (args.Length)
            {
                case 3:
                    inputPath = args[0];
                    outputPath = args[1];
                    versionInput = args[2];
                    modeInput = args[3];
                    networkInput = args[4];
                    break;
                default:
                case 0:

                    Console.WriteLine("Enter input path");
                    inputPath = @"" + Console.ReadLine();

                    Console.WriteLine("Enter output path");
                    outputPath = @"" + Console.ReadLine();

                    // Check input version
                    Console.WriteLine("Enter c for current Version 3.1.1 (defaults to 1.0.1j)");
                    versionInput = @"" + Console.ReadLine();

                    // Check input version
                    Console.WriteLine("Enter f for full handshake (defaults to partial)");
                    modeInput = @"" + Console.ReadLine();

                    // Check input version
                    Console.WriteLine("Enter n for network mode (defaults to local)");
                    networkInput = @"" + Console.ReadLine();

                    break;
            }

            if (!Directory.Exists(inputPath))
            {
                throw new Exception("Path doesn't exist:\t" + inputPath);
            }

            if (!Directory.Exists(outputPath))
            {
                throw new Exception("Path doesn't exist:\t" + outputPath);
            }

            // Check version; defaults to unpatched version
            version = versionInput switch
            {
                "c" => Version.current,
                _ => Version.old, //default to unpatched version
            };

            // Check handshakemode; defaults to partial handshake
            handshakeMode = modeInput switch
            {
                "f" => HandshakeMode.full,
                _ => HandshakeMode.partial, //default to unpatched version
            };

            // Check networkmode; defaults to partial handshake
            networkMode = networkInput switch
            {
                "n" => NetworkMode.network,
                _ => NetworkMode.local, //default to unpatched version
            };

            // Print input data directory
            Console.WriteLine("Input directory:\t" + inputPath);
            // Print output data directory
            Console.WriteLine("Output directory:\t" + outputPath);
            // Print used version
            Console.WriteLine(version);

            CsvConverter converter = new(inputPath, outputPath, version, handshakeMode, networkMode);
            (int, int, int) result = await converter.Run();

            Console.WriteLine($"Invalid .pcap files: {result.Item1}");
            Console.WriteLine($"Written datasets: {result.Item2}");
            Console.WriteLine($"Dropped deltas: {result.Item3}");
        }
    }
}
