using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapConverter
{    
    public static class ListExtensions
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
