using System;
using System.Threading;

namespace beio.Security
{
    public static class Crypto
    {
        private const int key_Size = 16;
        private const int IV_Size = 16;
        private const string baseKey = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789";
        private static readonly ThreadLocal<Random> rng = new ThreadLocal<Random>(() => new Random());
        public static byte[] MakeSecureKey()
        {
            byte[] SecureKey = new byte[key_Size + IV_Size];
            for (int i = 0; i < key_Size; ++i)
                SecureKey[IV_Size + i] = (byte)baseKey[rng.Value.Next(baseKey.Length)];
            rijndaelCipher.GenerateIV();
            rijndaelCipher.IV.CopyTo(SecureKey, 0);
            return SecureKey;
        }
        public static byte[] Encrypt(string textToEncrypt, byte[] SecureKey) 
        {
            byte[] Encrypt = System.Text.Encoding.UTF8.GetBytes(textToEncrypt);
            rijndaelCipher.Key = SecureKey.AsSpan(IV_Size, key_Size).ToArray();
            rijndaelCipher.IV = SecureKey.AsSpan(0, IV_Size).ToArray();
            using (var transform = rijndaelCipher.CreateEncryptor())
                return transform.TransformFinalBlock(Encrypt, 0, Encrypt.Length);
        }
        public static string Decrypt(byte[] textToDecrypt, byte[] SecureKey)
        {
            rijndaelCipher.Key = SecureKey.AsSpan(IV_Size, key_Size).ToArray();
            rijndaelCipher.IV = SecureKey.AsSpan(0, IV_Size).ToArray();
            using (var transform = rijndaelCipher.CreateDecryptor())
                return System.Text.Encoding.UTF8.GetString(transform.TransformFinalBlock(textToDecrypt, 0, textToDecrypt.Length));
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
}
