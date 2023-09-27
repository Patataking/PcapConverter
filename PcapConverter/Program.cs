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
            string? tlsVersionInput;
            string? modeInput;
            string? networkInput;
            TlsVersion tlsVersion;
            HandshakeMode handshakeMode;
            NetworkMode networkMode;

            // Check whether command line arguments have been supplied
            switch (args.Length)
            {
                // Handle input from command line
                case 4:
                    inputPath = args[0];
                    outputPath = args[1];
                    tlsVersionInput = args[2];
                    modeInput = args[3];
                    networkInput = args[4];
                    break;
                // In case of no command line arguments or an incorrect amount ask for input through console
                default:
                case 0:
                    Console.WriteLine("Enter input path");
                    inputPath = @"" + Console.ReadLine();

                    Console.WriteLine("Enter output path");
                    outputPath = @"" + Console.ReadLine();

                    Console.WriteLine("Enter 3 for TLS 1.3 (defaults to TLS 1.2)");
                    tlsVersionInput = @"" + Console.ReadLine();

                    Console.WriteLine("Enter f for full handshake (defaults to partial)");
                    modeInput = @"" + Console.ReadLine();

                    Console.WriteLine("Enter n for network mode (defaults to local)");
                    networkInput = @"" + Console.ReadLine();

                    break;
            }

            while (!Directory.Exists(inputPath))
            {
                Console.WriteLine("InputPath doesn't exist:\t" + inputPath);
                Console.WriteLine("Enter input path");
                inputPath = @"" + Console.ReadLine();
            }

            while (!Directory.Exists(outputPath))
            {
                Console.WriteLine("OutputPath doesn't exist:\t" + outputPath);
                Console.WriteLine("Enter output path");
                outputPath = @"" + Console.ReadLine();
            }

            // Check TLS version; defaults to TLS 1.2
            tlsVersion = tlsVersionInput switch
            {
                "3" => TlsVersion.three,
                "2" or _ => TlsVersion.two,
            };

            // Check handshakemode; defaults to partial handshake
            handshakeMode = modeInput switch
            {
                "f" => HandshakeMode.full,
                "p" or _ => HandshakeMode.partial,
            };

            // Check networkmode; defaults to local mode
            networkMode = networkInput switch
            {
                "n" => NetworkMode.network,
                "l" or _ => NetworkMode.local,
            };

            // Print input parameters
            Console.WriteLine("Input directory:\t" + inputPath);
            Console.WriteLine("Output directory:\t" + outputPath);
            Console.WriteLine("TLS version:\t" + tlsVersion);
            Console.WriteLine("Networkmode:\t" + tlsVersion);
            Console.WriteLine("Handshakemode:\t" + tlsVersion);

            CsvConverterConfig config = new(inputPath, outputPath, tlsVersion, handshakeMode, networkMode);
            CsvConverter converter = new(config);
            await converter.Run();
        }
    }
}
