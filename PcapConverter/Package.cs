using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
}
