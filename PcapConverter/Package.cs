namespace PcapConverter
{
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

        public Package(int index, double timeDelta, string info)
        {
            Index = index;
            TimeDelta = timeDelta;
            Info = info;
        }

        /// <summary>
        /// Converts a line of text from a .csv created by Tshark into a Package
        /// </summary>
        /// <param name="csvLine">A line of .txt</param>
        /// <returns>A new Package object</returns>
        public static Package FromCsv(string csvLine, bool isNetwork)
        {
            // Network traffic needs different logic
            if (isNetwork)
            {
                return FromCsvNetwork(csvLine);
            }
            /* Tshark produces extremely malformed .csv files that are not properly separated,
             * so we need to replace the irregular ammount of spaces used to separate relevant 
             * fields with tabs before we split the input. */
            string[] values = csvLine.TrimStart().Replace("    ", "\t").Replace("   ", "\t").Split('\t');
            // Confirm that the splitting has produced a correctly sized array.
            if (values.Length == 4)
            {
                // values[0] => Index | values[1] => TimeDelta | values[3] => Info | values[2] contains multiple irrelevant columns
                try
                {
                    return new(int.Parse(values[0]), double.Parse(values[1]), values[3]);
                }
                catch(FormatException) {
                    return new(-1, 0.0, "Malformed Package");
                }
            }
            return new(-1, 0.0, "Malformed Package");
        }

        /// <summary>
        /// Converts a line of text from a .csv created by Tshark into a Package. This method uses logic specific to network traffic which generates differently malformed .csv files than local packet captures.
        /// </summary>
        /// <param name="csvLine">A line of .txt</param>
        /// <returns>A new Package object</returns>
        public static Package FromCsvNetwork(string csvLine)
        {
            int index;
            double timeDelta;
            string info;
            /* TShark produces irregularly malformed .csv when analyzing network traffic.
             * Due to this we need do replace all occurences of any number of consecutive spaces with a single tab character */
            string[] values = csvLine.TrimStart().Replace("    ", "\t").Replace("   ", "\t").Replace(" ", "\t").Split('\t');

            if (values.Length >= 4)
            {
                try
                {
                    index = int.Parse(values[0]);
                    timeDelta = double.Parse(values[1]);
                }
                catch (FormatException)
                {
                    Console.WriteLine("Couldn't parse elapsed time");
                    Console.WriteLine(values[1]);
                    return new(-1, 0.0, "Malformed Package");
                }
                // We drop the Values between 2 & 4 as they are not relevant
                info = values[5];
                // The values from index 5 upwards contain the info field from wireshark. So we reassemble them back into a single string.
                for (int i = 6; i < values.Length; i++)
                {
                    info = info + " " + values[i];
                }
                // values[0] => Index | values[1] => TimeDelta | values[3] => Info | values[2] contains multiple irrelevant columns
                
                return new(index, timeDelta, info);
            }
            return new(-1, 0.0, "Malformed Package");
        }
    }
}
