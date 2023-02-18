
namespace PcapConverter
{    
    internal class Program
    {
        // Amount of erroneous .pcap files
        static int errors = 0;
        // Flag whether the unpatched version or patched version is used. Needed to filter the packages correctly.
        static bool isUnpatched = true;

        /// <summary>
        /// This program calculates time deltas from .csv files containing info from .pcap files
        /// The .csv files are created using Tshark
        /// </summary>
        /// <param name="_"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        static async Task Main(string[] _)
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

            // Check input version
            Console.WriteLine("Enter p for patched Version");
            var inp = @"" + Console.ReadLine();
            if (inp.Equals("p"))
            {
                isUnpatched = false;
            }            

            // Print data directory
            Console.WriteLine("Input directory:\t" + inputPath);
            // Print data directory
            Console.WriteLine("Output directory:\t" + outputPath);
            // Print used version
            Console.WriteLine(isUnpatched ? "Unpatched version" : "Patched version");

            // Get all subdirectories of input directory
            var directories = Directory.GetDirectories(inputPath).ToList();

            var deltas = new List<string>();
            var tasks = new List<Task<List<string>>>();

            // Go through all subdirectories & start a task for each to calculate deltas from .pcap files.
            directories.ForEach(directoryPath =>
            {

                tasks.Add(PcapsFromFolderToDeltasAsync(directoryPath));
            });

            while (tasks.Any())
            {
                // Wait for a task to finish
                Task<List<string>> finishedTask = await Task.WhenAny(tasks);
                // Remove finished task from task list
                tasks.Remove(finishedTask);
                // Add result of finished task to list of deltas
                deltas.AddRange( await finishedTask);
            }

            // Output amount of deltas
            Console.WriteLine(deltas.Count);            

            // Split deltas into subsets of 10000
            var dataSets = deltas.Partition(10000);
            int i = 1;
            dataSets.ForEach(dataSet =>
            {
                // Ensure that no incomplete set is written.
                if (dataSet.Count == 10000)
                {
                    System.IO.File.WriteAllLines(outputPath + $"\\{i}.txt", dataSet);
                    i++;
                };                
            });

            Console.WriteLine($"Invalid .pcap files: {errors}");
            Console.WriteLine($"Written datasets: {i-1}");
            Console.WriteLine($"Dropped deltas: {deltas.Count % 10000}");
        }
             
        /// <summary>
        /// Calculate all time deltas from any amount of .pcap files in a specified folder
        /// </summary>
        /// <param name="folder">The path to the folder</param>
        /// <returns>A List of strings containing the time deltas</returns>
        public static List<string> PcapsFromFolderToDeltas(string folder)
        {
            Console.WriteLine($"Current Folder: {folder}");
            // Get all deltas using optional double. If a .pcap is erroneous save null.
            List<double?> deltas = new();
            Directory.GetFiles(folder, "*.csv").ToList().ForEach(f => deltas.Add(PcapToDelta(f)));

            // Remove all null entries
            var timeDeltas = from delta in deltas
                                      where delta.HasValue
                                      select delta.Value.ToString();

            return timeDeltas.ToList();
        }

        /// <summary>
        /// Calculate all time deltas from any amount of .pcap files in a specified folder asynchronously
        /// </summary>
        /// <param name="folder">The path to the folder</param>
        /// <returns>A Task to calculate a list of strings containing the time deltas</returns>
        public static async Task<List<string>> PcapsFromFolderToDeltasAsync(string folder)
        {
            // Get all deltas using optional double. If a .pcap is erroneous save null.
            List<double?> deltas = new();
            await Task.Run(() => Directory.GetFiles(folder, "*.csv").ToList().ForEach(f => deltas.Add(PcapToDelta(f))));

            // Remove all null entries
            var timeDeltas = from delta in deltas
                             where delta.HasValue
                             select delta.Value.ToString();

            Console.WriteLine($"Finished Folder: {folder}");
            return timeDeltas.ToList();
        }

        /// <summary>
        /// Calculates the timedelta from a .pcap file
        /// </summary>
        /// <param name="path"></param>
        /// <returns>A double if the .pcap is valid or null if it's malformed.</returns>
        public static double? PcapToDelta(string path)
        {
            double? res = null;

            List<Package> packageList = File.ReadAllLines(path)
                                           .Select(v => Package.FromCsv(v))
                                           .ToList();


            IEnumerable<Package> startPackage;
            IEnumerable<Package> endPackage;

            // depending on the version the info column slightly varies.
            if (isUnpatched)
            {
                startPackage = from package in packageList
                                   where package.Info.Equals("TLSv1 379 Client Hello")
                                   select package;
                endPackage = from package in packageList
                                 where package.Info.StartsWith("TLSv1.2 198 Client Key Exchange")
                                 select package;
            }
            else
            {
                startPackage = from package in packageList
                               where package.Info.Equals("TLSv1 375 Client Hello")
                               select package;
                endPackage = from package in packageList
                                 where package.Info.StartsWith("TLSv1.2 194 Client Key Exchange")
                                 select package;                
            }            

            // Check if the pcap is malformed
            if (startPackage.Count() == 1 && endPackage.Count() == 1 && startPackage.First().Index == 4 && endPackage.First().Index == 8)
            {
                res = GetDelta(startPackage.Last(), endPackage.Last());
            } else 
            { 
                errors++; 
            }
                        
            return res;
        }
        /// <summary>
        /// Calculate the elapsed time between 2 packages.
        /// </summary>
        /// <param name="startPackage"></param>
        /// <param name="endPackage"></param>
        /// <returns></returns>
        public static double GetDelta(Package startPackage, Package endPackage)
        {
            return endPackage.TimeDelta - startPackage.TimeDelta;
        }
    }

    /// <summary>
    /// The Package class holds all relevant information from a single package in a .pcap file created by Wireshark.
    /// </summary>
    public class Package
    {        
        public int Index { get; set; }
        /// <summary>
        /// Contains the elapsed time since the start of the package capturing session
        /// </summary>
        public double TimeDelta { get; set; }
        /// <summary>
        /// This string corresponds to Wiresharks info column
        /// </summary>
        public string Info { get; set; }

        public Package(string index, string timeDelta, string info)
        {
            Index = int.Parse(index);
            TimeDelta = double.Parse(timeDelta);
            Info = info;
        }

        /// <summary>
        /// Converts a line of text from a .csv created by Tshark into a Package
        /// </summary>
        /// <param name="csvLine">A line of .txt</param>
        /// <returns>A new Package object</returns>
        public static Package FromCsv(string csvLine)
        {
            /* Tshark produces extremely malformed .csv files that are not properly separated,
             * so we need to replace the irregular ammount of spaces used to separate relevant 
             * fields with tabs before we split the input. */
            string[] values = csvLine.TrimStart().Replace("    ", "\t").Replace("   ", "\t").Split('\t');
            // Confirm that the splitting has produced a correctly sized array.
            if (values.Length == 4)
            {
                // values[0] => Index | values[1] => TimeDelta | values[3] => Info | values[2] contains multiple irrelevant columns
                return new(values[0], values[1], values[3]);
            }            
            return new("-1", "0.0", "Malformed Package");
        }
    }

    
    public static class Extensions
    {
        /// <summary>
        /// Split a List <paramref name="values"/> into multiples lists with <paramref name="chunkSize"/> length.
        /// </summary>
        /// <typeparam name="T">Generic type of List</typeparam>
        /// <param name="values">The List beeing split</param>
        /// <param name="chunkSize">The size of the created lists</param>
        /// <returns>A List of Lists of the specified size</returns>
        public static List<List<T>> Partition<T>(this List<T> values, int chunkSize)
        {
            return values.Select((x, i) => new { Index = i, Value = x })
                .GroupBy(x => x.Index / chunkSize)
                .Select(x => x.Select(v => v.Value).ToList())
                .ToList();
        }
    }
}
