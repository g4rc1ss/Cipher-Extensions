using System.IO;
using System.Security.Cryptography;

namespace Garciss.Symmetric.AES.Internal
{
    internal sealed class DecryptAESHelper
    {

        internal static string DecryptStringFromBytesAes(byte[] cipherText, byte[] keyParameter, byte[] iVparameter)
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = keyParameter;
                aesAlg.IV = iVparameter;
                using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                using (var msDecrypt = new MemoryStream(cipherText))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }
}
