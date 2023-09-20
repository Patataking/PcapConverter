using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapConverter
{
    enum TlsVersion
    {
        two,      // TLS 1.2
        three     // TLS 1.3 - currently not used
    }

    enum HandshakeMode
    {
        partial, // only look at the part of the handshake containing the side channel
        full
    }
    enum NetworkMode
    {
        network,
        local
    }

    internal class CsvConverterConfig
    {
        public readonly string InputPath;
        public readonly string OutputPath;
        public readonly TlsVersion TlsVersion;
        public readonly HandshakeMode HandshakeMode;
        public readonly NetworkMode NetworkMode;

        public CsvConverterConfig(string inputPath, string outputPath, TlsVersion version, HandshakeMode handshakeMode, NetworkMode networkMode)
        {
            InputPath = inputPath ?? throw new ArgumentNullException(nameof(inputPath));
            OutputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            TlsVersion = version;
            HandshakeMode = handshakeMode;
            NetworkMode = networkMode;
        }
    }
}
