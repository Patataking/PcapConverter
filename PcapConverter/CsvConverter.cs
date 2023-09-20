namespace PcapConverter
{  
    internal class CsvConverter
    {
        // Amount of erroneous .pcap files
        private int erroneousFiles = 0;
        // Amount of partial connections e.g. connections that lack the last package
        private int partialConnections = 0;
        // Amount of negative deltas e.g. connections where the ending package has an invalid timestamp 
        private int negativeDeltas = 0;
        // Amount of written datasets
        private int writtenDatasets = 0;
        public readonly CsvConverterConfig Config;

        public CsvConverter(string inputPath, string outputPath, TlsVersion version, HandshakeMode handshakeMode, NetworkMode networkMode)
        {
            Config = new CsvConverterConfig(inputPath, outputPath, version, handshakeMode, networkMode);
        }

        public CsvConverter(CsvConverterConfig config)
        {
            Config = config;
        }

        public async Task Run()
        {
            // Get all subdirectories of input directory
            var directories = Directory.GetDirectories(Config.InputPath).ToList();
            var tasks = new List<Task<List<string>>>();

            // Go through all subdirectories & start a task for each to calculate deltas from .pcap files
            directories.ForEach(directoryPath =>
            {
                tasks.Add(CsvFromFolderToDeltasAsync(directoryPath));
            });

            var deltas = new List<string>();

            while (tasks.Any())
            {
                // Wait for a task to finish
                Task<List<string>> finishedTask = await Task.WhenAny(tasks);
                // Remove finished task from task list
                tasks.Remove(finishedTask);
                // Add result of finished task to list of deltas
                deltas.AddRange(await finishedTask);
            }

            // Output amount of deltas
            Console.WriteLine(deltas.Count);

            // Split deltas into subsets of 10000
            var dataSets = deltas.Partition(10000);
            writtenDatasets = 1;
            dataSets.ForEach(dataSet =>
            {
                // Ensure that no incomplete set is written.
                if (dataSet.Count == 10000)
                {
                    File.WriteAllLines(Config.OutputPath + $"\\{writtenDatasets}.txt", dataSet);
                    writtenDatasets++;
                };
            });

            // Print information about dataset
            Console.WriteLine($"Invalid .pcap files: {erroneousFiles}");
            Console.WriteLine($"Written datasets: {writtenDatasets - 1}");
            Console.WriteLine($"Dropped deltas: {deltas.Count % 10000}");
            Console.WriteLine($"Negative deltas: {negativeDeltas}");
            Console.WriteLine($"Partial connections: {partialConnections}");
        }

        /// <summary>
        /// Calculate all time deltas from any amount of .csv files in a specified folder asynchronously
        /// </summary>
        /// <param name="folder">The path to the folder</param>
        /// <returns>A Task to calculate a list of strings containing the time deltas</returns>
        private async Task<List<string>> CsvFromFolderToDeltasAsync(string folder)
        {
            List<double> deltas = new();

            await Task.Run(() => Directory.GetFiles(folder, "*.csv").ToList().ForEach(f => deltas.AddRange(CsvToDelta(f))));

            // Remove all null entries
            var timeDeltas = from delta in deltas
                             select delta.ToString();

            Console.WriteLine($"Finished Folder: {folder}");
            return timeDeltas.ToList();
        }

        /// <summary>
        /// Calculates the timedelta from a .csv file
        /// </summary>
        /// <param name="path"></param>
        /// <returns>A double if the .csv is valid or null if it's malformed.</returns>
        private List<double> CsvToDelta(string path)
        {
            List<double> resList = new();
            List<Package> packageList;
            
            // Retrieve packages from file. 
            packageList = File.ReadAllLines(path)
                            .Select(v => Package.FromCsv(v, Config.NetworkMode == NetworkMode.network))
                            .ToList();

            var (startPackage, endPackage) = GetStartingAndEndingPackages(packageList);

            // Check if the pcap is malformed
            if (!ValidatePcap(startPackage, endPackage))
            {
                erroneousFiles++;
            }
            else
            {
                resList.AddRange(TryGetDeltas(startPackage, endPackage));
            }

            return resList;
        }

        /// <summary>
        /// Try to get get deltas from packet capture. Allows handling of partial connections without breaking.
        /// </summary>
        /// <param name="startPackage"></param>
        /// <param name="endPackage"></param>
        /// <returns></returns>
        private List<double> TryGetDeltas(IEnumerable<Package> startPackage, IEnumerable<Package> endPackage)
        {
            List<double> resList = new();
            for (int i = 0; i < startPackage.Count(); i++)
            {
                try
                {
                    var resTemp = GetDelta(startPackage.ElementAt(i), endPackage.ElementAt(i));
                    if (resTemp < 0)
                    {
                        negativeDeltas++;
                    }
                    else
                    {
                        resList.Add(resTemp);
                    }
                }
                catch
                {
                    partialConnections++;
                }                
            }
            return resList;
        }

        /// <summary>
        /// Validates the amounts and positions of packages for delta calculation
        /// </summary>
        /// <param name="startPackage"></param>
        /// <param name="endPackage"></param>
        /// <returns></returns>
        private bool ValidatePcap(IEnumerable<Package> startPackage, IEnumerable<Package> endPackage) => Config.NetworkMode switch
        {
            // Network mode may have multiple Connection per packet capture. Only the first connection is validated. Later connections might result in negative deltas.
            NetworkMode.network =>
                startPackage.Any() && endPackage.Any()
                && startPackage.First().Index < endPackage.First().Index,
            NetworkMode.local or _ =>
                startPackage.Count() == 1 && endPackage.Count() == 1
                && startPackage.First().Index == 4 && endPackage.First().Index > 4,
        };

        /// <summary>
        /// Retrieves all first and last packages per server connection.
        /// </summary>
        /// <param name="packageList">A list of packages from a single packet capture</param>
        /// <returns>A tuple containing (startPackages, endPackages)</returns>
        private (IEnumerable<Package>, IEnumerable<Package>) GetStartingAndEndingPackages(List<Package> packageList)
        {
            IEnumerable<Package> startPackage;
            IEnumerable<Package> endPackage;

            switch (Config.TlsVersion)
            {
                default:
                case TlsVersion.two:
                    startPackage = from package in packageList
                                   where package.Info.StartsWith("TLSv1") && package.Info.Contains("Client Hello")
                                   select package;
                    
                    endPackage = from package in packageList
                                 where package.Info.StartsWith("TLSv1.2")
                                    // The last package differs depending on whether a partial or full handshake is beeing analyzed.
                                    && Config.HandshakeMode switch
                                    {                                        
                                        HandshakeMode.full => package.Info.Contains("New Session Ticket, Change Cipher Spec, Encrypted Handshake Message"),
                                        _ or HandshakeMode.partial => package.Info.Contains("Server Hello, Certificate, Server Key Exchange, Server Hello Done")
                                    }
                                 select package;
                    break;
                case TlsVersion.three: // TODO
                    throw new NotImplementedException();
            }

            return (startPackage, endPackage);
        }

        /// <summary>
        /// Calculate the elapsed time between 2 packages.
        /// </summary>
        /// <param name="startPackage"></param>
        /// <param name="endPackage"></param>
        /// <returns></returns>
        private static double GetDelta(Package startPackage, Package endPackage)
        {
            return endPackage.TimeDelta - startPackage.TimeDelta;
        }

        ///<summary>
        /// Check if the packet capture uses time deltas relative to the start of the capture.
        /// </summary>
        /// <param name="packages">A list of packages</param>
        /// <returns>
        ///     <para>TRUE, if the package capture is in correct format </para>
        ///     <para>FALSE, if the time deltas are in relation to the previous package </para>
        /// </returns>
        private static bool ValidatePcapTimeDelta(IEnumerable<Package> packages)
        {
            double elapsedTime = 0;
            foreach (Package package in packages)
            {
                if (package.TimeDelta < elapsedTime)
                {
                    return false;
                }
                elapsedTime = package.TimeDelta;
            }
            return true;
        }
    }
}

