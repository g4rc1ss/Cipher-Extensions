using System.IO;
using System.Security.Cryptography;

namespace Garciss.Symmetric.AES.Internal
{
    internal sealed class EncryptAESHelper
    {

        internal static byte[] EncryptStringToBytesAes(string text, byte[] keyParameter, byte[] iVparameter)
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = keyParameter;
                aesAlg.IV = iVparameter;
                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }
                    }
                    return msEncrypt.ToArray();
                }
            }
        }
    }
}
