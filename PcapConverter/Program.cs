using System.IO;
using System.Runtime.InteropServices;
using static System.Net.Mime.MediaTypeNames;

namespace PcapConverter
{
    internal class Program
    {
        static int errors = 0;

        static readonly string workingDirectory = Environment.CurrentDirectory;
        static readonly string projectDirectory = Directory.GetParent(workingDirectory).Parent.Parent.FullName + "\\data\\";
        static void Main(string[] args)
        {
            Console.WriteLine("Enter input path");
            var inputPath = @"" + Console.ReadLine();

            if (!Directory.Exists(inputPath))
            {
                throw new Exception("Path doesn't exist:\t" + inputPath);
            }

            Console.WriteLine("Enter output path");
            var outputPath = @"" + Console.ReadLine();

            if (!Directory.Exists(outputPath))
            {
                throw new Exception("Path doesn't exist:\t" + outputPath);
            }

            // Print data directory
            Console.WriteLine("Input directory:\t" + inputPath);
            // Print data directory
            Console.WriteLine("Output directory:\t" + outputPath);

            //CreateCsvFiles(inputPath);


            
            var directories = Directory.GetDirectories(inputPath).ToList();
            directories.ForEach(directoryPath =>
            {
                var outputFilePath = outputPath + directoryPath.Split('\\').Last() + ".txt";
                // Write all deltas separated by newlines to file
                System.IO.File.WriteAllLines(outputFilePath, PcapsFromFolderToDeltas(directoryPath));
            });

            Console.WriteLine($"Invalid .pcap: {errors}");
            
            //var counts = ValidatePcaps(inputPath);
            //Console.WriteLine(counts);
        }

        /// <summary>
        /// Does not work!
        /// </summary>
        /// <param name="inputFolder"></param>
        public static void CreateCsvFiles(string inputFolder)
        {
            System.Diagnostics.ProcessStartInfo startInfo = new()
            {
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
                FileName = "cmd.exe"
            };

            var subFolders = Directory.GetDirectories(inputFolder).ToList();
            subFolders.ForEach(folderPath =>
            {
                var folderName = folderPath.Split('\\').Last();
                var files = Directory.GetFiles(folderPath).ToList();

                files.ForEach(file =>
                {
                var csvPath = projectDirectory + "tmp\\" + file.Split('\\').Last();
                //System.Diagnostics.Process.Start("CMD.exe", $"tshark - r {file} > {csvPath}");
                startInfo.Arguments = $"tshark - r {file} > {csvPath}";
                System.Diagnostics.Process.Start(startInfo);
                });
            });
        }

        public static List<Tuple<string, int, int>> ValidatePcaps(string path)
        {
            var result = new List<Tuple<string, int, int>>();            


            var directories = Directory.GetDirectories(path).ToList();
            directories.ForEach(directoryPath =>
            {
                var helloPackages = new List<Package>();
                var clientKeyExchangePackages = new List<Package>();

                Directory.GetFiles(directoryPath).ToList().ForEach(file =>
                {
                    List<Package> packageList = File.ReadAllLines(file)
                                               .Select(v => Package.FromCsv(v))
                                               .ToList();

                    var startPackage = from package in packageList
                                       where package.Info.Equals("TLSv1 375 Client Hello")
                                       select package;
                    var endPackage = from package in packageList
                                     where package.Info.StartsWith("TLSv1.2 194 Client Key Exchange")
                                     select package;

                    helloPackages.AddRange(startPackage);
                    clientKeyExchangePackages.AddRange(endPackage);
                });

                result.Add(new Tuple<string, int, int>(directoryPath ,helloPackages.Count, clientKeyExchangePackages.Count));
            });

            return result;
        }

        public static List<string> PcapsFromFolderToDeltas(string folder)
        {            
            // Get all files in data directory and calculate time deltas
            List<int?> deltas = new();
            Directory.GetFiles(folder).ToList().ForEach(f => deltas.Add(PcapToDelta(f)));
            var timeDeltas = from delta in deltas
                                      where delta.HasValue
                                      select delta.Value.ToString();

            return timeDeltas.ToList();
        }

        public static int? PcapToDelta(string path)
        {
            int? res = null;

            List<Package> packageList = File.ReadAllLines(path)
                                           .Select(v => Package.FromCsv(v))
                                           .ToList();

            var startPackage = from package in packageList
                               where package.Info.Equals("TLSv1 375 Client Hello")
                               select package;
            var endPackage = from package in packageList
                             where package.Info.StartsWith("TLSv1.2 194 Client Key Exchange")
                             select package;

            if (startPackage.Count() == 1 && endPackage.Count() == 1 && startPackage.First().Id == 4 && endPackage.First().Id == 8)
            {
                res = GetDelta(startPackage.Last(), endPackage.Last());
            } else { errors++; }
                        
            return res;
        }

        public static int GetDelta(Package startPackage, Package endPackage)
        {
            return endPackage.TimeDelta - startPackage.TimeDelta;
        }
    }

    public class Package
    {
        public int Id { get; set; }
        public int TimeDelta { get; set; }
        public string Info { get; set; }

        public Package(string id, string timeDelta, string info)
        {
            Id = int.Parse(id);
            TimeDelta = int.Parse(timeDelta.Split('.')[1]);
            Info = info;
        }

        public static Package FromCsv(string csvLine)
        {
            string[] values = csvLine.TrimStart().Replace("    ", "\t").Replace("   ", "\t").Split('\t');
            Package package = new(values[0], values[1], values[3]);
            return package;
        }
    }
}
