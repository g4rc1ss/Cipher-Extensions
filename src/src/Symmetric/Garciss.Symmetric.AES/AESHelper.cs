using System;
using System.Security.Cryptography;
using System.Text;
using Garciss.Symmetric.AES.Internal;

namespace Garciss.Symmetric.AES;

/// <summary>
/// Clase con metodos y atributos para facilitar el uso de la clase 
/// [System.Security.Cryptography].Aes
/// </summary>
public static class AESHelper
{

    /// <summary>
    /// Metodo usado para encriptar una cadena con el algoritmo de cifrado AES
    /// </summary>
    /// <param name="text"></param>
    /// <param name="keyParameter"></param>
    /// <param name="iVparameter"></param>
    /// <returns></returns>
    public static byte[] EncriptarTexto(string text, byte[] keyParameter, byte[] iVparameter)
    {
        ValidarCampos(text, keyParameter, iVparameter);
        return EncryptAESHelper.EncryptStringToBytesAes(text, keyParameter, iVparameter);
    }


    /// <summary>
    /// Metodo para descifrar una array de bytes cifrados en algoritmo AES
    /// </summary>
    /// <param name="cipherText"></param>
    /// <param name="keyParameter"></param>
    /// <param name="iVparameter"></param>
    /// <returns></returns>
    public static string DesencriptarTexto(byte[] cipherText, byte[] keyParameter, byte[] iVparameter)
    {
        ValidarCampos(cipherText, keyParameter, iVparameter);
        return DecryptAESHelper.DecryptStringFromBytesAes(cipherText, keyParameter, iVparameter);
    }

    /// <summary>
    /// Funcion que devuelve la clave en un array de bytes para poder cifrar o descifrar
    /// </summary>
    /// <param name="clave">Ingresas la clave en string</param>
    /// <param name="key">Devuelve la Key</param>
    /// <param name="iv">Devuelve el IV</param>
    /// <returns></returns>
    public static bool CreateKeyIV(string clave, out byte[] key, out byte[] iv)
    {
        using (var crear = Aes.Create())
        {
            crear.KeySize = 256;
            using (HashAlgorithm hash = SHA256.Create())
            {
                key = hash.ComputeHash(Encoding.Unicode.GetBytes(clave));
            }
            iv = crear.IV;
        }
        return true;
    }

    private static void ValidarCampos(params object[] campos)
    {
        foreach (var field in campos)
        {
            if (field is null)
            {
                throw new ArgumentNullException(nameof(field), "Uno de los parametros enviados al metodo es null");
            }
        }
    }
}
