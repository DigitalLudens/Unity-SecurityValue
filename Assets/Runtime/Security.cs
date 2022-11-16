using System;
using System.Collections.Generic;

namespace beio.Security
{
    public static class Crypto
    {
        private const int key_Size = 16;
        private const string baseKey = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789";
        public static string MakeSecureKey()
        {
            List<char> MakeKey = new List<char>();
            for (int i = 0; i < key_Size; ++i)
                MakeKey.Add(baseKey[UnityEngine.Random.Range(0, baseKey.Length - 1)]);
            return new string(MakeKey.ToArray());
        }
        public static string Encrypt(string textToEncrypt, string key)
        {
            byte[] plainText = Encrypt(System.Text.Encoding.UTF8.GetBytes(textToEncrypt), key);
            return System.Text.Encoding.UTF8.GetString(plainText);
        }
        public static byte[] Encrypt(byte[] Encrypt, string key)
        {
            string KeyString = ConvertKey(key);
            rijndaelCipher.Key = System.Text.Encoding.Default.GetBytes(KeyString);
            rijndaelCipher.IV = System.Text.Encoding.Default.GetBytes(KeyString);
            System.Security.Cryptography.ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            string Base64 = Convert.ToBase64String(transform.TransformFinalBlock(Encrypt, 0, Encrypt.Length));
            return System.Text.Encoding.UTF8.GetBytes(Base64);
        }
        public static string Decrypt(string textToDecrypt, string key)
        {
            byte[] plainText = Decrypt(System.Text.Encoding.UTF8.GetBytes(textToDecrypt), key);
            return System.Text.Encoding.UTF8.GetString(plainText);
        }
        public static byte[] Decrypt(byte[] Decrypt, string key)
        {
            Decrypt = Base64Check(Decrypt);
            Decrypt = Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(Decrypt));
            string KeyString = ConvertKey(key);
            rijndaelCipher.Key = System.Text.Encoding.Default.GetBytes(KeyString);
            rijndaelCipher.IV = System.Text.Encoding.Default.GetBytes(KeyString);
            return rijndaelCipher.CreateDecryptor(rijndaelCipher.Key, rijndaelCipher.IV).TransformFinalBlock(Decrypt, 0, Decrypt.Length);
        }
        public static string Base64Check(string input)
        {
            return System.Text.Encoding.UTF8.GetString(Base64Check(System.Text.Encoding.UTF8.GetBytes(input)));
        }
        public static byte[] Base64Check(byte[] input)
        {
            List<byte> data = new List<byte>(input);
            data = data.FindAll(s => s < 128);
            return data.ToArray();
        }
        #region private
        private static string ConvertKey(string iv)
        {
            if (key_Size < iv.Length) iv = iv.Substring(0, key_Size);
            return iv;
        }

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