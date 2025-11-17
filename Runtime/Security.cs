using System;
using System.Collections.Generic;

namespace beio.Security
{
    public static class Crypto
    {
        private const int key_Size = 16;
        private const string baseKey = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789";
        public static char[] MakeSecureKey()
        {
            char[] SecureKey = new char[key_Size];
            for (int i = 0; i < key_Size; ++i)
                SecureKey[i] = baseKey[UnityEngine.Random.Range(0, baseKey.Length - 1)];
            return SecureKey;
        }
        public static string Encrypt(string textToEncrypt, char[] SecureKey)
        {
            byte[] plainText = Encrypt(System.Text.Encoding.UTF8.GetBytes(textToEncrypt), key);
            return System.Text.Encoding.UTF8.GetString(plainText);
        }
        private static byte[] Encrypt(byte[] Encrypt, char[] SecureKey)
        {
            rijndaelCipher.Key = SecureKey;
            rijndaelCipher.IV = SecureKey;
            System.Security.Cryptography.ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            return Convert.ToBase64String(transform.TransformFinalBlock(Encrypt, 0, Encrypt.Length));
        }
        public static string Decrypt(string textToDecrypt, char[] SecureKey)
        {
            byte[] plainText = Decrypt(System.Text.Encoding.UTF8.GetBytes(textToDecrypt), SecureKey);
            return System.Text.Encoding.UTF8.GetString(plainText);
        }
        private static byte[] Decrypt(byte[] Decrypt, char[] SecureKey)
        {
            Decrypt = Convert.FromBase64String(Decrypt);
            rijndaelCipher.Key = SecureKey;
            rijndaelCipher.IV = SecureKey;
            return rijndaelCipher.CreateDecryptor(rijndaelCipher.Key, rijndaelCipher.IV).TransformFinalBlock(Decrypt, 0, Decrypt.Length);
        }

        #region private

        private static System.Security.Cryptography.RijndaelManaged rijndaelCipher = new System.Security.Cryptography.RijndaelManaged
        {
            Mode = System.Security.Cryptography.CipherMode.CBC,
            Padding = System.Security.Cryptography.PaddingMode.PKCS7,
            KeySize = 128,
            BlockSize = 128
        };
        #endregion

    }
    public class Xor
    {
        public static void Encrypt(byte[] data, string keyString)
        {
            byte[] key = System.Text.Encoding.ASCII.GetBytes(keyString);
            int j = 0;
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= key[j];
                j = (j + 1) % key.Length;
            }
        }
        public static void Decrypt(byte[] data, string keyString) => Encrypt(data, keyString);
    }
}
