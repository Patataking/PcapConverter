using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace PcapConverter
{
    enum Version
    {
        old,  // OpenSSL Version 1.0.1j
        current     // OpenSSL Version 3.1.1
    }

    enum HandshakeMode
    {
        partial, // only look at the part of the handshake containing the side channel
        full
    }

    internal class CsvConverter
    {
        // Amount of erroneous .pcap files
        int errors = 0;
        private readonly string InputPath;
        private readonly string OutputPath;
        private readonly Version Version;
        private readonly HandshakeMode HandshakeMode;

        public CsvConverter(string InputPath, string OutputPath, Version Version, HandshakeMode handshakeMode) {
            this.InputPath = InputPath ?? throw new ArgumentNullException(nameof(InputPath));
            this.OutputPath = OutputPath ?? throw new ArgumentNullException(nameof(OutputPath));
            this.Version = Version;
            this.HandshakeMode = handshakeMode;
        }

        public async Task<(int, int, int)> Run()
        {
            // Get all subdirectories of input directory
            var directories = Directory.GetDirectories(InputPath).ToList();
            var tasks = new List<Task<List<string>>>();

            // Go through all subdirectories & start a task for each to calculate deltas from .pcap files.
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
            int i = 1;
            dataSets.ForEach(dataSet =>
            {
                // Ensure that no incomplete set is written.
                if (dataSet.Count == 10000)
                {
                    System.IO.File.WriteAllLines(OutputPath + $"\\{i}.txt", dataSet);
                    i++;
                };
            });           

            return (errors, i - 1, deltas.Count % 10000);
        }

        /// <summary>
        /// Calculate all time deltas from any amount of .pcap files in a specified folder
        /// </summary>
        /// <param name="folder">The path to the folder</param>
        /// <returns>A List of strings containing the time deltas</returns>
        public List<string> PcapsFromFolderToDeltas(string folder)
        {
            Console.WriteLine($"Current Folder: {folder}");
            // Get all deltas using optional double. If a .pcap is erroneous save null.
            List<double?> deltas = new();
            Directory.GetFiles(folder, "*.csv").ToList().ForEach(f => deltas.Add(CsvToDelta(f)));

            // Remove all null entries
            var timeDeltas = from delta in deltas
                             where delta.HasValue
                             select delta.Value.ToString();

            return timeDeltas.ToList();
        }

        /// <summary>
        /// Calculate all time deltas from any amount of .csv files in a specified folder asynchronously
        /// </summary>
        /// <param name="folder">The path to the folder</param>
        /// <returns>A Task to calculate a list of strings containing the time deltas</returns>
        public async Task<List<string>> CsvFromFolderToDeltasAsync(string folder)
        {
            // Get all deltas using optional double. If a .csv is erroneous save null.
            List<double?> deltas = new();
            await Task.Run(() => Directory.GetFiles(folder, "*.csv").ToList().ForEach(f => deltas.Add(CsvToDelta(f))));

            // Remove all null entries
            var timeDeltas = from delta in deltas
                             where delta.HasValue
                             select delta.Value.ToString();

            Console.WriteLine($"Finished Folder: {folder}");
            return timeDeltas.ToList();
        }

        /// <summary>
        /// Calculates the timedelta from a .csv file
        /// </summary>
        /// <param name="path"></param>
        /// <returns>A double if the .csv is valid or null if it's malformed.</returns>
        public double? CsvToDelta(string path)
        {
            double? res = null;

            List<Package> packageList = File.ReadAllLines(path)
                                           .Select(v => Package.FromCsv(v))
                                           .ToList();


            IEnumerable<Package> startPackage;
            IEnumerable<Package> endPackage;            

            switch (Version)
            {
                default:
                case Version.old:
                    startPackage = from package in packageList
                                   where package.Info.StartsWith("TLSv1") && package.Info.Contains("Client Hello")
                                   select package;
                    if (HandshakeMode == HandshakeMode.partial)
                    {                        
                        endPackage = from package in packageList
                                     where package.Info.StartsWith("TLSv1.2 8") && package.Info.Contains("Server Hello, Certificate, Server Key Exchange, Server Hello Done")
                                     select package;
                    } else
                    {                        
                        endPackage = from package in packageList
                                     where package.Info.Equals("TLSv1.2 298 New Session Ticket, Change Cipher Spec, Encrypted Handshake Message")
                                     select package;
                    }                    
                    break;
                case Version.current: // TODO
                    startPackage = new List<Package>(); 
                    endPackage = new List<Package>();
                    break;

            }

            // Check if the pcap is malformed
            if (startPackage.Count() == 1 && endPackage.Count() == 1 && startPackage.First().Index == 4 && endPackage.First().Index > 4)
            {
                res = GetDelta(startPackage.Last(), endPackage.Last());
                if (res < 0)
                {
                    res = null;
                    errors++;
                }
            }
            else
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

        ///<summary>
        /// Check if the packet capture uses time deltas relative to the start of the capture.
        /// </summary>
        /// <param name="packages">A list of packages</param>
        /// <returns>
        ///     <para>TRUE, if the package capture is in correct format </para>
        ///     <para>FALSE, if the time deltas are in relation to the previous package </para>
        /// </returns>
        public static bool ValidatePcapTimeDelta(IEnumerable<Package> packages)
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

