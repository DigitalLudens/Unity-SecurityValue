using System;


namespace beio.Security
{
    public class Variable<T>
    {
        #region Private Member
        private byte[] secureKey;
        private byte[] secureValue;

        #endregion
        #region Static Method
        #region Variable Type Cast
        public static implicit operator Variable<T>(T a)
        {
            return new Variable<T>(a);
        }
        public static implicit operator T(Variable<T> a)
        {
            if (a == null)
                a = new Variable<T>();
            return a.value;
        }
        private delegate bool TryParseFunc(string s, out T value);
        private static readonly TryParseFunc tryParseFunc = CreateTryParseFunc();
        private static TryParseFunc CreateTryParseFunc()
        {
            var t = typeof(T);
            if (t == typeof(string))
                return (string s, out T v) =>
                {
                    v = (T)(object)s;
                    return true;
                };

            var mi = t.GetMethod("TryParse", new[] { typeof(string), t.MakeByRefType() });
            if (mi == null) return null;

            try
            {
                return (TryParseFunc)Delegate.CreateDelegate(typeof(TryParseFunc), mi);
                //return Delegate.CreateDelegate(typeof(TryParseFunc), mi) as TryParseFunc;
            }
            catch
            {
                return null;
            }
        }
        public override string ToString()
        {
            return value.ToString();
        }
        #endregion
        #endregion
        #region Constructor
        public Variable()
        {
        }
        public Variable(T value) : this()
        {
            secureKey = Crypto.MakeSecureKey();
            secureValue = Crypto.Encrypt(value.ToString(), secureKey);
        }
        #endregion
        public T value
        {
            get
            {
                if(secureKey == null || secureValue == null)
                    return default;
                // 암호화 해제한 값
                try
                {
                    string DecryptValue = Crypto.Decrypt(secureValue, secureKey);
                    if (tryParseFunc != null && tryParseFunc(DecryptValue, out var parsed))
                        return parsed;
                    return default;
                }
                catch
                {
                    return default;    
                }
                
            }
            set
            {
                secureKey = Crypto.MakeSecureKey();
                secureValue = Crypto.Encrypt(value.ToString(), secureKey);
            }
        }
    }

}
